#!/usr/bin/env node
/**
 * Google Sheets MCP Server — Streamable HTTP, BROKER-FIRST (auth model "B").
 *
 * This MCP holds ZERO Google secrets. It is a *client* of the Connections Broker
 * (https://connectionsbroker.agenticledger.ai), which is the registered Google
 * OAuth app, owns the client_id/secret, runs the consent flow, and vaults +
 * auto-refreshes each user's token. See AUTH.md for the full design.
 *
 * Credential resolution (per request):
 *   1. Broker-first (default): derive the caller's `principal`, sign a short-lived
 *      JWT, ask the broker POST /token for provider=google -> { accessToken },
 *      call the Sheets API directly. If not connected yet, return a
 *      connect-on-first-call message with the broker consent URL (never hard-errors).
 *   2. Raw passthrough escape hatch (holds no secret): if the caller sends
 *      `Authorization: Bearer <raw-google-access-token>` (a ya29.* access token),
 *      it is used directly. Note: because this MCP no longer holds a Google client
 *      secret, a raw *refresh* token can no longer be exchanged here — pass an
 *      access token, or use the broker.
 *
 * Principal transport (the platform-gateway contract — see AUTH.md):
 *   - `X-Broker-Principal: <instanceId>:<agentId>` set by the gateway (per-agent).
 *   - Optional `X-Broker-Principal-Sig` (HMAC) enforced when BROKER_PRINCIPAL_HMAC_KEY
 *     is set — makes the header unforgeable on the public Railway host.
 *   - No header -> BROKER_FALLBACK_PRINCIPAL (standalone single-principal mode).
 */

import { randomUUID, createHmac } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { zodToJsonSchema as _zodToJsonSchema } from 'zod-to-json-schema';
import { GSheetsClient } from './api-client.js';
import { tools } from './tools.js';
import {
  brokerConfigured,
  brokerBaseUrl,
  brokerClientNamespace,
  brokerProvider,
  resolveToken,
  startConnect,
} from './broker-client.js';

function zodToJsonSchema(schema: any): any {
  return _zodToJsonSchema(schema);
}

// --- Config ---
const PORT = parseInt(process.env.PORT || '3196', 10);
const SERVER_BASE_URL = process.env.SERVER_BASE_URL || `http://localhost:${PORT}`;

// --- Principal transport (platform-gateway contract) ---
const PRINCIPAL_HEADER = (process.env.BROKER_PRINCIPAL_HEADER || 'x-broker-principal').toLowerCase();
const PRINCIPAL_SIG_HEADER = 'x-broker-principal-sig';
const PRINCIPAL_HMAC_KEY = process.env.BROKER_PRINCIPAL_HMAC_KEY || '';
const FALLBACK_PRINCIPAL = process.env.BROKER_FALLBACK_PRINCIPAL || 'default';

function headerValue(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Derive the broker `principal` for this request. Returns an error only when a
 * principal header is present but its HMAC signature fails (integrity mode).
 */
function derivePrincipal(req: express.Request): { principal: string } | { error: string } {
  const raw = headerValue(req.headers[PRINCIPAL_HEADER]);
  if (raw && raw.trim()) {
    const principal = raw.trim();
    if (PRINCIPAL_HMAC_KEY) {
      const sig = headerValue(req.headers[PRINCIPAL_SIG_HEADER]);
      const expected = createHmac('sha256', PRINCIPAL_HMAC_KEY).update(principal).digest('base64url');
      if (!sig || sig !== expected) {
        return { error: `Missing or invalid ${PRINCIPAL_SIG_HEADER} for the supplied ${PRINCIPAL_HEADER}` };
      }
    }
    return { principal };
  }
  // No principal header -> standalone single-principal mode.
  return { principal: FALLBACK_PRINCIPAL };
}

/** Raw passthrough escape hatch — holds no secret. Returns a raw Google access token. */
function rawPassthrough(req: express.Request): string | null {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const bearer = auth.replace(/^Bearer\s+/i, '').trim();
  return bearer || null;
}

// --- Express app ---
const app = express();
app.use(express.json());
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use('/static', express.static(path.join(__dirname, 'public')));

// ==================== OAuth Authorization Server Metadata ====================
// Claude-CLI OAuth-trap fix: OAuth Authorization Server metadata stays
// de-advertised. The spec discovery path /.well-known/oauth-authorization-server
// 404s, so Claude CLI never auto-initiates an OAuth dance — it uses the broker path.
app.get('/_disabled/oauth-authorization-server', (_req, res) => {
  res.status(404).json({ error: 'not_found' });
});

// ==================== SMART ROOT / LANDING ====================
app.get('/', (_req, res) => {
  res.json({
    name: 'Google Sheets MCP Server',
    provider: 'AgenticLedger',
    version: '2.0.0',
    description: 'Read, write, create, and manage Google Sheets spreadsheets via MCP.',
    mcpEndpoint: '/mcp',
    transport: 'streamable-http',
    tools: tools.length,
    auth: {
      model: 'broker-first',
      description:
        'Credentials are owned by the Connections Broker. On first use the tool returns a one-time connect link; after you connect once, calls just work. No secret is ever pasted into this MCP.',
      broker: brokerBaseUrl,
      principalHeader: PRINCIPAL_HEADER,
      alternativeAuth: {
        type: 'bearer-passthrough',
        description:
          'Escape hatch (no secret held): pass a raw Google access token (ya29.*) as Bearer.',
      },
    },
    configTemplate: {
      mcpServers: {
        googlesheets: {
          url: `${SERVER_BASE_URL}/mcp`,
        },
      },
    },
    links: {
      health: '/health',
      documentation: 'https://googlesheetsmcp.agenticledger.ai/googlesheets/',
    },
  });
});

// ==================== HEALTH CHECK ====================
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    server: 'gsheets-mcp-http',
    version: '2.0.0',
    tools: tools.length,
    transport: 'streamable-http',
    authModel: 'broker-first',
    brokerConfigured,
    brokerBaseUrl,
    brokerProvider,
    clientNamespace: brokerConfigured ? brokerClientNamespace : null,
    authModes: [
      'broker-first (default): resolves Google via the Connections Broker',
      'bearer-passthrough (escape hatch): Authorization: Bearer <google-access-token>',
    ],
  });
});

// ==================== MCP SERVER ====================

interface SessionState {
  server: Server;
  transport: StreamableHTTPServerTransport;
}

const sessions = new Map<string, SessionState>();

/**
 * Resolves a GSheetsClient for the current caller at tool-call time, or a
 * connect-on-first-call message, or an error. Bound per session.
 */
type ClientResolution =
  | { kind: 'client'; client: GSheetsClient }
  | { kind: 'connect'; message: string }
  | { kind: 'error'; message: string };

type ClientResolver = () => Promise<ClientResolution>;

function createMCPServer(resolveClient: ClientResolver): Server {
  const server = new Server(
    { name: 'gsheets-mcp-server', version: '2.0.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: tools.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: zodToJsonSchema(tool.inputSchema),
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const tool = tools.find((t) => t.name === name);
    if (!tool) {
      throw new Error(`Unknown tool: ${name}`);
    }

    const resolved = await resolveClient();
    if (resolved.kind === 'connect') {
      // Connect-on-first-call: not an error — surface the one-time connect link.
      return { content: [{ type: 'text' as const, text: resolved.message }] };
    }
    if (resolved.kind === 'error') {
      return { content: [{ type: 'text' as const, text: `Error: ${resolved.message}` }], isError: true };
    }

    try {
      const result = await tool.handler(resolved.client, args as any);
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: 'text' as const, text: `Error: ${message}` }],
        isError: true,
      };
    }
  });

  return server;
}

/** Build the connect-on-first-call structured message. */
async function connectMessage(principal: string): Promise<string> {
  const started = await startConnect(principal);
  if ('error' in started) {
    return `Google isn't connected for this caller yet, and starting a connection failed: ${started.error}`;
  }
  return JSON.stringify(
    {
      status: 'connection_required',
      provider: brokerProvider,
      message:
        'Google is not connected for this caller yet. Open the connect link below once (sign in to Google and grant access), then run the tool again — it will work.',
      connectUrl: started.authorizeUrl,
    },
    null,
    2
  );
}

// POST /mcp — MCP session entry point
app.post('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  // Existing session
  if (sessionId && sessions.has(sessionId)) {
    const { transport } = sessions.get(sessionId)!;
    await transport.handleRequest(req, res, req.body);
    return;
  }

  // New session — pick the credential resolver.
  let resolveClient: ClientResolver;

  const raw = rawPassthrough(req);
  if (raw) {
    const client = new GSheetsClient(raw, '', '');
    resolveClient = async () => ({ kind: 'client', client });
  } else {
    if (!brokerConfigured) {
      res.status(503).json({
        error: 'Broker not configured on this server.',
        hint: 'Set BROKER_INSTALL_BEARER, BROKER_JWT_KEY, BROKER_CLIENT_NAMESPACE (from the broker /register).',
        alternative: {
          'Authorization': 'Bearer <your-google-access-token>',
        },
      });
      return;
    }
    const derived = derivePrincipal(req);
    if ('error' in derived) {
      res.status(401).json({ error: derived.error });
      return;
    }
    const principal = derived.principal;
    resolveClient = async () => {
      const tok = await resolveToken(principal);
      if (tok.status === 'connected') {
        return { kind: 'client', client: new GSheetsClient(tok.accessToken, '', '') };
      }
      if (tok.status === 'not_connected') {
        return { kind: 'connect', message: await connectMessage(principal) };
      }
      return { kind: 'error', message: tok.message };
    };
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
  });

  const server = createMCPServer(resolveClient);

  transport.onclose = () => {
    const sid = transport.sessionId;
    if (sid) {
      sessions.delete(sid);
      console.log(`[mcp] Session closed: ${sid}`);
    }
  };

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);

  const newSessionId = transport.sessionId;
  if (newSessionId) {
    sessions.set(newSessionId, { server, transport });
    console.log(`[mcp] New session: ${newSessionId} (mode: ${raw ? 'passthrough' : 'broker'})`);
  }
});

// GET /mcp — SSE stream for server notifications
app.get('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !sessions.has(sessionId)) {
    res.status(400).json({ error: 'Invalid or missing session. Send initialization POST first.' });
    return;
  }
  const { transport } = sessions.get(sessionId)!;
  await transport.handleRequest(req, res);
});

// DELETE /mcp — close session
app.delete('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !sessions.has(sessionId)) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  const { transport, server } = sessions.get(sessionId)!;
  await transport.close();
  await server.close();
  sessions.delete(sessionId);
  res.status(200).json({ status: 'session closed' });
});

// ==================== START ====================
app.listen(PORT, () => {
  console.log(`Google Sheets MCP HTTP Server v2.0.0 (broker-first)`);
  console.log(`  MCP endpoint:   ${SERVER_BASE_URL}/mcp`);
  console.log(`  Health check:   ${SERVER_BASE_URL}/health`);
  console.log(`  Tools:          ${tools.length}`);
  console.log(`  Transport:      Streamable HTTP`);
  console.log(`  Auth model:     broker-first (${brokerConfigured ? 'broker configured' : 'BROKER NOT CONFIGURED'})`);
  console.log(`  Broker:         ${brokerBaseUrl}`);
  console.log(`  Provider:       ${brokerProvider}`);
  console.log(`  Principal:      header '${PRINCIPAL_HEADER}'${PRINCIPAL_HMAC_KEY ? ' (HMAC-verified)' : ''}, fallback '${FALLBACK_PRINCIPAL}'`);
});
