#!/usr/bin/env node
/**
 * Google Sheets MCP Server — Exposed via Streamable HTTP
 *
 * Auth model: Google OAuth 2.0 with stateless refresh-token passthrough.
 * 1. User visits /authorize → redirected to Google consent screen
 * 2. Google redirects back with auth code → server exchanges for tokens
 * 3. Server RETURNS refresh_token to client (does NOT store it)
 * 4. Client stores refresh_token locally, sends as Bearer on each request
 * 5. Server exchanges refresh_token for access_token, calls Sheets API, discards
 *
 * Also supports OAuth 2.0 Client Credentials for agent platforms.
 * Server stores NO permanent credentials.
 */

import { randomUUID } from 'node:crypto';
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

function zodToJsonSchema(schema: any): any {
  return _zodToJsonSchema(schema);
}

const PORT = parseInt(process.env.PORT || '3196', 10);
const SERVER_BASE_URL = process.env.SERVER_BASE_URL || `http://localhost:${PORT}`;
const SLUG = 'googlesheets';

// Google OAuth credentials (set on Railway)
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI = `${SERVER_BASE_URL}/oauth/callback`;
const GOOGLE_SCOPES = [
  'https://www.googleapis.com/auth/spreadsheets',
].join(' ');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- OAuth token store (in-memory, for agent platform Client Credentials flow) ---
const TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

interface OAuthToken {
  refreshToken: string;
  expiresAt: number;
}

const oauthTokens = new Map<string, OAuthToken>();

// Cleanup expired tokens every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of oauthTokens) {
    if (now > data.expiresAt) oauthTokens.delete(token);
  }
}, 10 * 60 * 1000);

// --- Pending auth codes (for Google OAuth callback) ---
interface PendingAuth {
  code: string;
  expiresAt: number;
}
const pendingAuths = new Map<string, PendingAuth>();

// --- Static assets (logo) ---
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use('/static', express.static(path.join(__dirname, 'public')));

// Health check (no auth required)
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    server: 'gsheets-mcp-http',
    version: '1.0.0',
    tools: tools.length,
    transport: 'streamable-http',
    auth: 'google-oauth',
    auth_modes: ['google-oauth-refresh-token', 'oauth-client-credentials'],
  });
});

// --- OAuth 2.0 Discovery ---
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: SERVER_BASE_URL,
    authorization_endpoint: `${SERVER_BASE_URL}/authorize`,
    token_endpoint: `${SERVER_BASE_URL}/oauth/token`,
    revocation_endpoint: `${SERVER_BASE_URL}/oauth/revoke`,
    registration_endpoint: `${SERVER_BASE_URL}/oauth/register`,
    grant_types_supported: ['authorization_code', 'client_credentials'],
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    service_documentation: `https://googlesheetsmcp.agenticledger.ai/${SLUG}/`,
  });
});

// --- Dynamic Client Registration (for Claude.ai Cowork) ---
app.post('/oauth/register', (_req, res) => {
  res.status(201).json({
    client_id: SLUG,
    client_name: 'Google Sheets MCP Server',
    redirect_uris: [`${SERVER_BASE_URL}/oauth/callback`],
  });
});

// --- Google OAuth: Step 1 — Redirect to Google ---
app.get('/authorize', (req, res) => {
  const state = req.query.state as string || randomUUID();

  const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  googleAuthUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID);
  googleAuthUrl.searchParams.set('redirect_uri', GOOGLE_REDIRECT_URI);
  googleAuthUrl.searchParams.set('response_type', 'code');
  googleAuthUrl.searchParams.set('scope', GOOGLE_SCOPES);
  googleAuthUrl.searchParams.set('access_type', 'offline');
  googleAuthUrl.searchParams.set('prompt', 'consent');
  googleAuthUrl.searchParams.set('state', state);

  res.redirect(googleAuthUrl.toString());
});

// --- Google OAuth: Step 2 — Callback from Google ---
app.get('/oauth/callback', async (req, res) => {
  const { code, error, state } = req.query;

  if (error) {
    res.status(400).send(`<h2>Authorization Failed</h2><p>${error}</p><p><a href="/authorize">Try again</a></p>`);
    return;
  }

  if (!code) {
    res.status(400).send('<h2>Missing authorization code</h2>');
    return;
  }

  try {
    // Exchange auth code for tokens
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: GOOGLE_REDIRECT_URI,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
      }),
    });

    if (!tokenResponse.ok) {
      const text = await tokenResponse.text();
      res.status(500).send(`<h2>Token exchange failed</h2><pre>${text}</pre>`);
      return;
    }

    const tokenData = await tokenResponse.json() as {
      access_token: string;
      refresh_token?: string;
      expires_in: number;
      scope: string;
    };

    if (!tokenData.refresh_token) {
      res.status(400).send(`
        <h2>No refresh token received</h2>
        <p>Google only returns a refresh token on the first authorization.
        Please <a href="https://myaccount.google.com/permissions" target="_blank">revoke access</a>
        for this app, then <a href="/authorize">try again</a>.</p>
      `);
      return;
    }

    // Return the refresh token to the user — server does NOT store it
    res.send(CALLBACK_SUCCESS_HTML.replace('{{REFRESH_TOKEN}}', tokenData.refresh_token));
  } catch (err) {
    res.status(500).send(`<h2>Error</h2><pre>${err}</pre>`);
  }
});

// --- OAuth 2.0 Client Credentials (for agent platforms) ---
// Client sends refresh_token as client_secret, gets back mcp_ token
app.post('/oauth/token', (req, res) => {
  const { grant_type, client_id, client_secret, code, code_verifier, redirect_uri } = req.body;

  // Authorization Code exchange (for Claude.ai Cowork PKCE flow)
  if (grant_type === 'authorization_code') {
    if (!code) {
      res.status(400).json({ error: 'invalid_request', error_description: 'Missing authorization code' });
      return;
    }
    res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Use /authorize flow to get a refresh token, then use client_credentials with refresh_token as client_secret' });
    return;
  }

  if (grant_type !== 'client_credentials') {
    res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Supported: client_credentials' });
    return;
  }

  if (client_id !== SLUG) {
    res.status(400).json({ error: 'invalid_client', error_description: `client_id must be "${SLUG}"` });
    return;
  }

  if (!client_secret) {
    res.status(400).json({ error: 'invalid_request', error_description: 'client_secret is required (your Google refresh token)' });
    return;
  }

  // client_secret IS the user's Google refresh token
  const accessToken = `mcp_${randomUUID().replace(/-/g, '')}`;
  const expiresIn = TOKEN_TTL_MS / 1000;

  oauthTokens.set(accessToken, {
    refreshToken: client_secret,
    expiresAt: Date.now() + TOKEN_TTL_MS,
  });

  res.json({
    access_token: accessToken,
    token_type: 'bearer',
    expires_in: expiresIn,
  });
});

// --- OAuth 2.0 Token Revocation ---
app.post('/oauth/revoke', (req, res) => {
  const { token } = req.body;
  if (token) oauthTokens.delete(token);
  res.status(200).json({ status: 'revoked' });
});

// --- Smart root route ---
app.get('/', (req, res) => {
  const accept = req.headers.accept || '';
  if (accept.includes('text/html')) {
    res.send(BRANDED_LANDING_HTML);
    return;
  }
  res.json({
    name: 'Google Sheets MCP Server',
    provider: 'AgenticLedger',
    version: '1.0.0',
    description: 'Read, write, create, and manage Google Sheets spreadsheets via MCP',
    mcpEndpoint: '/mcp',
    transport: 'streamable-http',
    tools: tools.length,
    auth: {
      type: 'google-oauth',
      description: 'Authorize via Google OAuth to get a refresh token, then pass it as Bearer',
      authorize_url: `${SERVER_BASE_URL}/authorize`,
      modes: {
        bearer: {
          description: 'Pass your Google refresh token as the Bearer token',
          header: 'Authorization: Bearer <your-google-refresh-token>',
        },
        oauth: {
          description: 'Exchange refresh token for a time-limited session token',
          token_endpoint: `${SERVER_BASE_URL}/oauth/token`,
          client_id: SLUG,
          client_secret: '<your-google-refresh-token>',
          grant_type: 'client_credentials',
        },
      },
    },
    configTemplate: {
      mcpServers: {
        googlesheets: {
          url: `${SERVER_BASE_URL}/mcp`,
          headers: { Authorization: 'Bearer <your-google-refresh-token>' },
        },
      },
    },
    links: {
      health: '/health',
      authorize: '/authorize',
      documentation: `https://googlesheetsmcp.agenticledger.ai/${SLUG}/`,
      oauth_discovery: '/.well-known/oauth-authorization-server',
    },
  });
});

// --- Resolve refresh token from request ---
function resolveRefreshToken(req: express.Request): string | null {
  const auth = req.headers.authorization;
  if (!auth) return null;

  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) return null;

  // Mode 1: OAuth-issued mcp_ token → look up refresh token
  if (token.startsWith('mcp_')) {
    const entry = oauthTokens.get(token);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      oauthTokens.delete(token);
      return null;
    }
    return entry.refreshToken;
  }

  // Mode 2: Raw refresh token passthrough
  return token;
}

// --- Per-session state ---
interface SessionState {
  server: Server;
  transport: StreamableHTTPServerTransport;
  client: GSheetsClient;
}

const sessions = new Map<string, SessionState>();

function createMCPServer(client: GSheetsClient): Server {
  const server = new Server(
    { name: 'gsheets-mcp-server', version: '1.0.0' },
    { capabilities: { tools: {} } },
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

    if (!tool) throw new Error(`Unknown tool: ${name}`);

    try {
      const result = await tool.handler(client, args as any);
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

// --- Streamable HTTP endpoint ---
app.post('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  // Existing session
  if (sessionId && sessions.has(sessionId)) {
    const { transport } = sessions.get(sessionId)!;
    await transport.handleRequest(req, res, req.body);
    return;
  }

  // New session — requires Bearer token (refresh token or mcp_ token)
  const refreshToken = resolveRefreshToken(req);
  if (!refreshToken) {
    res.status(401).json({
      error: 'Missing or invalid Authorization header.',
      how_to_authorize: `Visit ${SERVER_BASE_URL}/authorize to connect your Google account and get a refresh token.`,
      modes: {
        bearer: 'Authorization: Bearer <your-google-refresh-token>',
        oauth: `POST ${SERVER_BASE_URL}/oauth/token with client_id=${SLUG}&client_secret=<refresh-token>&grant_type=client_credentials`,
      },
    });
    return;
  }

  // Create per-session Sheets client
  const client = new GSheetsClient(refreshToken, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
  });

  const server = createMCPServer(client);

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
    sessions.set(newSessionId, { server, transport, client });
    console.log(`[mcp] New session: ${newSessionId}`);
  }
});

// GET /mcp — SSE stream
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

// ==================== CALLBACK SUCCESS PAGE ====================
const CALLBACK_SUCCESS_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Google Sheets Connected — AgenticLedger</title>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root{--primary:#2563EB;--fg:#0F172A;--muted:#64748B;--surface:#F8FAFC;--border:#E2E8F0;--success:#10B981;--success-light:#D1FAE5;}
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:'DM Sans',sans-serif;color:var(--fg);min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--surface);}
    .card{background:#fff;border:1px solid var(--border);border-radius:16px;padding:40px;max-width:560px;width:100%;margin:20px;box-shadow:0 1px 3px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.06);}
    .success-icon{font-size:48px;text-align:center;margin-bottom:12px;}
    .title{font-size:20px;font-weight:700;text-align:center;color:var(--success);margin-bottom:20px;}
    .section{margin:20px 0;font-size:13px;color:var(--muted);}
    .token-box{position:relative;background:#1E293B;border-radius:12px;padding:16px;margin:12px 0;font-family:'JetBrains Mono',monospace;font-size:12px;color:#E2E8F0;word-break:break-all;line-height:1.6;}
    .copy-btn{position:absolute;top:8px;right:8px;background:rgba(255,255,255,.1);color:#CBD5E1;border:1px solid rgba(255,255,255,.15);border-radius:6px;padding:4px 10px;font-size:11px;cursor:pointer;}
    .copy-btn:hover{background:rgba(255,255,255,.2);color:#fff;}
    .copy-btn.copied{background:rgba(16,185,129,.3);color:#86EFAC;}
    .warning{background:#FEF3C7;border:1px solid #FDE68A;border-radius:10px;padding:12px;font-size:12px;color:#92400E;margin:16px 0;}
    .config-pre{background:#1E293B;border-radius:12px;padding:16px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#E2E8F0;white-space:pre;overflow-x:auto;margin:12px 0;line-height:1.7;}
  </style>
</head>
<body>
  <div class="card">
    <div class="success-icon">&#x2705;</div>
    <div class="title">Google Sheets Connected Successfully!</div>
    <div class="section">
      <p>Your Google refresh token is shown below. <strong>Save it now</strong> — it will not be shown again. The server does not store it.</p>
    </div>
    <div class="token-box">
      <button class="copy-btn" onclick="copyToken(this)">Copy</button>
      <span id="refreshToken">{{REFRESH_TOKEN}}</span>
    </div>
    <div class="warning">
      <strong>Keep this token secure.</strong> It grants access to your Google Sheets. Store it in your local mcp-keys/.env file.
    </div>
    <div class="section">
      <p><strong>MCP Configuration:</strong></p>
      <div class="config-pre" id="configBlock"></div>
    </div>
    <div class="section">
      <p><strong>For MyAgent gateway:</strong> Save to your agent's mcp-keys/gsheets.env:</p>
      <div class="config-pre">GSHEETS_REFRESH_TOKEN={{REFRESH_TOKEN}}</div>
    </div>
  </div>
  <script>
    var token = document.getElementById('refreshToken').textContent;
    document.getElementById('configBlock').textContent = JSON.stringify({mcpServers:{googlesheets:{url:"${SERVER_BASE_URL}/mcp",headers:{Authorization:"Bearer "+token}}}},null,2);
    function copyToken(btn){
      navigator.clipboard.writeText(token).then(function(){
        btn.textContent='Copied!';btn.classList.add('copied');
        setTimeout(function(){btn.textContent='Copy';btn.classList.remove('copied');},2000);
      });
    }
  </script>
</body>
</html>`;

// ==================== BRANDED LANDING HTML ====================
const BRANDED_LANDING_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Google Sheets MCP Server — AgenticLedger</title>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root{--primary:#2563EB;--primary-dark:#1D4ED8;--primary-light:#DBEAFE;--primary-50:#EFF6FF;--fg:#0F172A;--muted:#64748B;--surface:#F8FAFC;--border:#E2E8F0;--success:#10B981;--success-light:#D1FAE5;--google:#0F9D58;}
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:'DM Sans',sans-serif;color:var(--fg);min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--surface);background-image:linear-gradient(135deg,var(--primary-50) 0%,var(--surface) 50%,#F0F9FF 100%);background-size:400% 400%;animation:gradientShift 15s ease infinite;}
    @keyframes gradientShift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
    .card{background:#fff;border:1px solid var(--border);border-radius:16px;padding:40px;max-width:560px;width:100%;margin:20px;box-shadow:0 1px 3px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.06);animation:slideUp .5s ease-out;}
    @keyframes slideUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
    .header{display:flex;align-items:center;gap:14px;margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid var(--border);}
    .header img{height:36px;}
    .header span{font-size:18px;font-weight:700;color:var(--fg);}
    .status-badge{display:inline-flex;align-items:center;gap:6px;background:var(--success-light);border:1px solid #A7F3D0;border-radius:20px;padding:6px 14px;font-size:13px;font-weight:600;color:#065F46;margin-bottom:20px;}
    .status-badge::before{content:'';width:8px;height:8px;border-radius:50%;background:var(--success);animation:pulse 2s infinite;}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
    .info-grid{display:grid;gap:12px;margin-bottom:24px;}
    .info-row{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:var(--primary-50);border-radius:10px;font-size:13px;}
    .info-row .label{color:var(--muted);font-weight:500;}
    .info-row .value{color:var(--fg);font-weight:600;font-family:'JetBrains Mono',monospace;font-size:12px;}
    .connect-btn{display:block;width:100%;padding:14px;border-radius:12px;border:none;background:var(--google);color:#fff;font-family:'DM Sans',sans-serif;font-size:15px;font-weight:600;cursor:pointer;text-align:center;text-decoration:none;margin:20px 0;transition:all .2s;}
    .connect-btn:hover{background:#0B8043;transform:translateY(-1px);box-shadow:0 4px 12px rgba(15,157,88,.3);}
    .section-title{font-size:14px;font-weight:600;color:var(--fg);margin:24px 0 10px;}
    .steps{font-size:13px;color:var(--muted);line-height:1.8;}
    .steps ol{margin:8px 0 0 20px;}
    .trust{display:flex;gap:16px;flex-wrap:wrap;padding-top:20px;border-top:1px solid var(--border);}
    .trust-item{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);}
    .trust-item svg{width:14px;height:14px;color:var(--success);}
    .footer{padding-top:16px;border-top:1px solid var(--border);text-align:center;font-size:12px;color:var(--muted);margin-top:20px;}
  </style>
</head>
<body>
  <div class="card">
    <div class="header"><img src="/static/logo.png" alt="AgenticLedger"><span>Google Sheets MCP</span></div>
    <div class="status-badge">Server Online</div>
    <div class="info-grid">
      <div class="info-row"><span class="label">Tools</span><span class="value">\${tools.length}</span></div>
      <div class="info-row"><span class="label">Transport</span><span class="value">Streamable HTTP</span></div>
      <div class="info-row"><span class="label">Auth</span><span class="value">Google OAuth 2.0</span></div>
    </div>
    <a href="/authorize" class="connect-btn">Connect Your Google Sheets</a>
    <div class="section-title">How it works</div>
    <div class="steps">
      <ol>
        <li>Click <strong>Connect Your Google Sheets</strong> above</li>
        <li>Sign in with your Google account and grant permissions</li>
        <li>Copy the refresh token shown on the success page</li>
        <li>Use the token as your Bearer credential in MCP config</li>
      </ol>
      <p style="margin-top:12px;font-size:12px">Your refresh token stays on your device. This server stores nothing.</p>
    </div>
    <div class="trust">
      <div class="trust-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>No credentials stored</div>
      <div class="trust-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>Stateless</div>
      <div class="trust-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>Per-session auth</div>
    </div>
    <div class="footer">Powered by AgenticLedger &middot; <a href="https://googlesheetsmcp.agenticledger.ai/" target="_blank" style="color:var(--primary);text-decoration:none">Explore Other MCPs</a></div>
  </div>
</body>
</html>`;

app.listen(PORT, () => {
  console.log(`Google Sheets MCP HTTP Server running on port ${PORT}`);
  console.log(`  MCP endpoint:    ${SERVER_BASE_URL}/mcp`);
  console.log(`  Authorize:       ${SERVER_BASE_URL}/authorize`);
  console.log(`  OAuth token:     ${SERVER_BASE_URL}/oauth/token`);
  console.log(`  OAuth discovery: ${SERVER_BASE_URL}/.well-known/oauth-authorization-server`);
  console.log(`  Health check:    ${SERVER_BASE_URL}/health`);
  console.log(`  Landing page:    ${SERVER_BASE_URL}/`);
  console.log(`  Tools:           ${tools.length}`);
  console.log(`  Transport:       Streamable HTTP`);
  console.log(`  Auth:            Google OAuth (refresh token passthrough)`);
});
