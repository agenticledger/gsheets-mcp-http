/**
 * Google Sheets API Client
 * Auth: Takes a Google OAuth refresh token, exchanges for access token per request.
 * Base URL: https://sheets.googleapis.com/v4
 */

const BASE_URL = 'https://sheets.googleapis.com/v4';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';

export class GSheetsClient {
  private refreshToken: string;
  private clientId: string;
  private clientSecret: string;
  private cachedAccessToken: string | null = null;
  private tokenExpiresAt: number = 0;

  constructor(refreshToken: string, clientId: string, clientSecret: string) {
    this.refreshToken = refreshToken;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
  }

  private async getAccessToken(): Promise<string> {
    // Use cached token if still valid (with 60s buffer)
    if (this.cachedAccessToken && Date.now() < this.tokenExpiresAt - 60_000) {
      return this.cachedAccessToken;
    }

    const response = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: this.refreshToken,
        client_id: this.clientId,
        client_secret: this.clientSecret,
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Google token refresh failed (${response.status}): ${text}`);
    }

    const data = await response.json() as { access_token: string; expires_in: number };
    this.cachedAccessToken = data.access_token;
    this.tokenExpiresAt = Date.now() + data.expires_in * 1000;
    return data.access_token;
  }

  private async request<T>(
    method: string,
    endpoint: string,
    params?: Record<string, string | number | boolean | undefined>,
    body?: any,
  ): Promise<T> {
    const accessToken = await this.getAccessToken();
    const url = new URL(`${BASE_URL}${endpoint}`);

    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.append(key, String(value));
        }
      });
    }

    const options: RequestInit = {
      method,
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    };

    const response = await fetch(url.toString(), options);

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Google Sheets API Error ${response.status}: ${text}`);
    }

    if (response.status === 204) return {} as T;
    return response.json();
  }

  // === Spreadsheet Metadata ===

  async getSpreadsheet(spreadsheetId: string, includeGridData = false) {
    return this.request<any>('GET', `/spreadsheets/${encodeURIComponent(spreadsheetId)}`, {
      includeGridData,
    });
  }

  // === Read Range ===

  async readRange(spreadsheetId: string, range: string, valueRenderOption = 'FORMATTED_VALUE') {
    return this.request<any>(
      'GET',
      `/spreadsheets/${encodeURIComponent(spreadsheetId)}/values/${encodeURIComponent(range)}`,
      { valueRenderOption },
    );
  }

  // === Write Range ===

  async writeRange(
    spreadsheetId: string,
    range: string,
    values: any[][],
    valueInputOption = 'USER_ENTERED',
  ) {
    return this.request<any>(
      'PUT',
      `/spreadsheets/${encodeURIComponent(spreadsheetId)}/values/${encodeURIComponent(range)}`,
      { valueInputOption },
      { range, values },
    );
  }

  // === Append Rows ===

  async appendRows(
    spreadsheetId: string,
    range: string,
    values: any[][],
    valueInputOption = 'USER_ENTERED',
    insertDataOption = 'INSERT_ROWS',
  ) {
    return this.request<any>(
      'POST',
      `/spreadsheets/${encodeURIComponent(spreadsheetId)}/values/${encodeURIComponent(range)}:append`,
      { valueInputOption, insertDataOption },
      { range, values },
    );
  }

  // === Create Spreadsheet ===

  async createSpreadsheet(title: string, sheetTitles?: string[]) {
    const sheets = sheetTitles?.map((t) => ({ properties: { title: t } }));
    return this.request<any>('POST', '/spreadsheets', undefined, {
      properties: { title },
      ...(sheets ? { sheets } : {}),
    });
  }

  // === List Sheets (tabs) ===

  async listSheets(spreadsheetId: string) {
    const spreadsheet = await this.getSpreadsheet(spreadsheetId);
    return {
      spreadsheetId: spreadsheet.spreadsheetId,
      title: spreadsheet.properties?.title,
      sheets: (spreadsheet.sheets || []).map((s: any) => ({
        sheetId: s.properties?.sheetId,
        title: s.properties?.title,
        index: s.properties?.index,
        rowCount: s.properties?.gridProperties?.rowCount,
        columnCount: s.properties?.gridProperties?.columnCount,
      })),
    };
  }

  // === Add Sheet (tab) ===

  async addSheet(spreadsheetId: string, title: string) {
    return this.request<any>(
      'POST',
      `/spreadsheets/${encodeURIComponent(spreadsheetId)}:batchUpdate`,
      undefined,
      {
        requests: [{ addSheet: { properties: { title } } }],
      },
    );
  }

  // === Clear Range ===

  async clearRange(spreadsheetId: string, range: string) {
    return this.request<any>(
      'POST',
      `/spreadsheets/${encodeURIComponent(spreadsheetId)}/values/${encodeURIComponent(range)}:clear`,
      undefined,
      {},
    );
  }

  // === Batch Read ===

  async batchGetValues(spreadsheetId: string, ranges: string[], valueRenderOption = 'FORMATTED_VALUE') {
    const accessToken = await this.getAccessToken();
    const url = new URL(`${BASE_URL}/spreadsheets/${encodeURIComponent(spreadsheetId)}/values:batchGet`);
    ranges.forEach((r) => url.searchParams.append('ranges', r));
    url.searchParams.set('valueRenderOption', valueRenderOption);

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
      },
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Google Sheets API Error ${response.status}: ${text}`);
    }

    return response.json();
  }

  // === Batch Write ===

  async batchUpdateValues(
    spreadsheetId: string,
    data: Array<{ range: string; values: any[][] }>,
    valueInputOption = 'USER_ENTERED',
  ) {
    return this.request<any>(
      'POST',
      `/spreadsheets/${encodeURIComponent(spreadsheetId)}/values:batchUpdate`,
      undefined,
      {
        valueInputOption,
        data: data.map((d) => ({
          range: d.range,
          majorDimension: 'ROWS',
          values: d.values,
        })),
      },
    );
  }

  // === Delete Sheet (tab) ===

  async deleteSheet(spreadsheetId: string, sheetId: number) {
    return this.request<any>(
      'POST',
      `/spreadsheets/${encodeURIComponent(spreadsheetId)}:batchUpdate`,
      undefined,
      {
        requests: [{ deleteSheet: { sheetId } }],
      },
    );
  }
}
