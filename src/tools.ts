import { z } from 'zod';
import { GSheetsClient } from './api-client.js';

interface ToolDef {
  name: string;
  description: string;
  inputSchema: z.ZodType<any>;
  handler: (client: GSheetsClient, args: any) => Promise<any>;
}

export const tools: ToolDef[] = [
  // === Get Spreadsheet ===
  {
    name: 'sheets_get_spreadsheet',
    description: 'Get spreadsheet metadata including title, sheets (tabs), and properties.',
    inputSchema: z.object({
      spreadsheet_id: z.string().describe('The Google Spreadsheet ID (from the URL)'),
    }),
    handler: async (client, args) => {
      const spreadsheet = await client.getSpreadsheet(args.spreadsheet_id);
      return {
        spreadsheetId: spreadsheet.spreadsheetId,
        title: spreadsheet.properties?.title,
        locale: spreadsheet.properties?.locale,
        timeZone: spreadsheet.properties?.timeZone,
        sheets: (spreadsheet.sheets || []).map((s: any) => ({
          sheetId: s.properties?.sheetId,
          title: s.properties?.title,
          index: s.properties?.index,
          rowCount: s.properties?.gridProperties?.rowCount,
          columnCount: s.properties?.gridProperties?.columnCount,
        })),
      };
    },
  },

  // === Read Range ===
  {
    name: 'sheets_read_range',
    description: 'Read a cell range from a spreadsheet (e.g., "Sheet1!A1:D10"). Returns a 2D array of values.',
    inputSchema: z.object({
      spreadsheet_id: z.string().describe('The Google Spreadsheet ID'),
      range: z.string().describe('The A1 notation range to read (e.g., "Sheet1!A1:D10", "Sheet1!A:A")'),
      value_render_option: z.enum(['FORMATTED_VALUE', 'UNFORMATTED_VALUE', 'FORMULA']).default('FORMATTED_VALUE').describe('How values should be rendered'),
    }),
    handler: async (client, args) => {
      return client.readRange(args.spreadsheet_id, args.range, args.value_render_option);
    },
  },

  // === Write Range ===
  {
    name: 'sheets_write_range',
    description: 'Write data to a cell range. Accepts a 2D array of values. Overwrites existing data in the range.',
    inputSchema: z.object({
      spreadsheet_id: z.string().describe('The Google Spreadsheet ID'),
      range: z.string().describe('The A1 notation range to write (e.g., "Sheet1!A1:D3")'),
      values: z.array(z.array(z.any())).describe('2D array of values to write, e.g., [["Name","Age"],["Alice",30]]'),
      value_input_option: z.enum(['RAW', 'USER_ENTERED']).default('USER_ENTERED').describe('How input data should be interpreted'),
    }),
    handler: async (client, args) => {
      return client.writeRange(args.spreadsheet_id, args.range, args.values, args.value_input_option);
    },
  },

  // === Append Rows ===
  {
    name: 'sheets_append_rows',
    description: 'Append rows to the end of a sheet. Data is added after the last row with content.',
    inputSchema: z.object({
      spreadsheet_id: z.string().describe('The Google Spreadsheet ID'),
      range: z.string().describe('The A1 notation of the table range to append to (e.g., "Sheet1!A:D")'),
      values: z.array(z.array(z.any())).describe('2D array of rows to append, e.g., [["Alice",30],["Bob",25]]'),
      value_input_option: z.enum(['RAW', 'USER_ENTERED']).default('USER_ENTERED').describe('How input data should be interpreted'),
    }),
    handler: async (client, args) => {
      return client.appendRows(args.spreadsheet_id, args.range, args.values, args.value_input_option);
    },
  },

  // === Create Spreadsheet ===
  {
    name: 'sheets_create',
    description: 'Create a new Google Spreadsheet. Returns the spreadsheet ID and URL.',
    inputSchema: z.object({
      title: z.string().describe('Title for the new spreadsheet'),
      sheet_titles: z.array(z.string()).optional().describe('Optional list of sheet tab names to create (default: one "Sheet1")'),
    }),
    handler: async (client, args) => {
      const result = await client.createSpreadsheet(args.title, args.sheet_titles);
      return {
        spreadsheetId: result.spreadsheetId,
        title: result.properties?.title,
        url: result.spreadsheetUrl,
        sheets: (result.sheets || []).map((s: any) => ({
          sheetId: s.properties?.sheetId,
          title: s.properties?.title,
        })),
      };
    },
  },

  // === Add Sheet ===
  {
    name: 'sheets_add_sheet',
    description: 'Add a new sheet tab to an existing spreadsheet.',
    inputSchema: z.object({
      spreadsheet_id: z.string().describe('The Google Spreadsheet ID'),
      title: z.string().describe('Title for the new sheet tab'),
    }),
    handler: async (client, args) => {
      const result = await client.addSheet(args.spreadsheet_id, args.title);
      const addedSheet = result.replies?.[0]?.addSheet?.properties;
      return {
        sheetId: addedSheet?.sheetId,
        title: addedSheet?.title,
        index: addedSheet?.index,
      };
    },
  },

  // === Clear Range ===
  {
    name: 'sheets_clear_range',
    description: 'Clear all values from a cell range (keeps formatting). The cells become empty.',
    inputSchema: z.object({
      spreadsheet_id: z.string().describe('The Google Spreadsheet ID'),
      range: z.string().describe('The A1 notation range to clear (e.g., "Sheet1!A1:D10")'),
    }),
    handler: async (client, args) => {
      return client.clearRange(args.spreadsheet_id, args.range);
    },
  },

  // === Batch Read ===
  {
    name: 'sheets_batch_read',
    description: 'Read multiple ranges from a spreadsheet in a single request. More efficient than multiple individual reads.',
    inputSchema: z.object({
      spreadsheet_id: z.string().describe('The Google Spreadsheet ID'),
      ranges: z.array(z.string()).describe('Array of A1 notation ranges to read (e.g., ["Sheet1!A1:B5", "Sheet2!A1:C10"])'),
      value_render_option: z.enum(['FORMATTED_VALUE', 'UNFORMATTED_VALUE', 'FORMULA']).default('FORMATTED_VALUE').describe('How values should be rendered'),
    }),
    handler: async (client, args) => {
      return client.batchGetValues(args.spreadsheet_id, args.ranges, args.value_render_option);
    },
  },

  // === Batch Write ===
  {
    name: 'sheets_batch_write',
    description: 'Write to multiple ranges in a spreadsheet in a single request. More efficient than multiple individual writes.',
    inputSchema: z.object({
      spreadsheet_id: z.string().describe('The Google Spreadsheet ID'),
      data: z.array(z.object({
        range: z.string().describe('A1 notation range to write to'),
        values: z.array(z.array(z.any())).describe('2D array of values for this range'),
      })).describe('Array of range+values pairs to write'),
      value_input_option: z.enum(['RAW', 'USER_ENTERED']).default('USER_ENTERED').describe('How input data should be interpreted'),
    }),
    handler: async (client, args) => {
      return client.batchUpdateValues(args.spreadsheet_id, args.data, args.value_input_option);
    },
  },

  // === Delete Sheet ===
  {
    name: 'sheets_delete_sheet',
    description: 'Delete a sheet (tab) from a spreadsheet by its numeric sheet ID. Use sheets_get_spreadsheet or sheets_list_sheets first to find sheet IDs.',
    inputSchema: z.object({
      spreadsheet_id: z.string().describe('The Google Spreadsheet ID'),
      sheet_id: z.number().describe('The numeric sheet ID to delete (not the sheet name — use sheets_list_sheets to find it)'),
    }),
    handler: async (client, args) => {
      return client.deleteSheet(args.spreadsheet_id, args.sheet_id);
    },
  },
];
