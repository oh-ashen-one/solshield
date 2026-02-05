/**
 * Anchor IDL Parser
 * 
 * Parses Anchor IDL JSON files to extract program structure
 * for security analysis.
 */

import { readFileSync, existsSync } from 'fs';

export interface ParsedIdl {
  name: string;
  version: string;
  instructions: IdlInstruction[];
  accounts: IdlAccount[];
  types: IdlType[];
  events: IdlEvent[];
  errors: IdlError[];
  raw: any;
}

export interface IdlInstruction {
  name: string;
  accounts: IdlAccountRef[];
  args: IdlArg[];
}

export interface IdlAccountRef {
  name: string;
  isMut: boolean;
  isSigner: boolean;
  isOptional?: boolean;
  pda?: any;
}

export interface IdlArg {
  name: string;
  type: string | object;
}

export interface IdlAccount {
  name: string;
  type: {
    kind: string;
    fields: IdlField[];
  };
}

export interface IdlField {
  name: string;
  type: string | object;
}

export interface IdlType {
  name: string;
  type: any;
}

export interface IdlEvent {
  name: string;
  fields: IdlField[];
}

export interface IdlError {
  code: number;
  name: string;
  msg?: string;
}

/**
 * Parse an Anchor IDL file
 */
export function parseIdlFile(filePath: string): ParsedIdl {
  if (!existsSync(filePath)) {
    throw new Error(`IDL file not found: ${filePath}`);
  }
  
  const content = readFileSync(filePath, 'utf-8');
  return parseIdlContent(content);
}

/**
 * Parse IDL JSON content
 */
export function parseIdlContent(content: string): ParsedIdl {
  let idl: any;
  
  try {
    idl = JSON.parse(content);
  } catch (e) {
    throw new Error('Invalid IDL JSON');
  }
  
  return {
    name: idl.name || 'unknown',
    version: idl.version || '0.0.0',
    instructions: parseInstructions(idl.instructions || []),
    accounts: parseAccounts(idl.accounts || []),
    types: idl.types || [],
    events: idl.events || [],
    errors: idl.errors || [],
    raw: idl,
  };
}

function parseInstructions(instructions: any[]): IdlInstruction[] {
  return instructions.map(ix => ({
    name: ix.name,
    accounts: (ix.accounts || []).map((acc: any) => ({
      name: acc.name,
      isMut: acc.isMut || false,
      isSigner: acc.isSigner || false,
      isOptional: acc.isOptional || false,
      pda: acc.pda,
    })),
    args: (ix.args || []).map((arg: any) => ({
      name: arg.name,
      type: arg.type,
    })),
  }));
}

function parseAccounts(accounts: any[]): IdlAccount[] {
  return accounts.map(acc => ({
    name: acc.name,
    type: {
      kind: acc.type?.kind || 'struct',
      fields: (acc.type?.fields || []).map((f: any) => ({
        name: f.name,
        type: f.type,
      })),
    },
  }));
}

/**
 * Check if content looks like an IDL
 */
export function isIdlContent(content: string): boolean {
  try {
    const parsed = JSON.parse(content);
    return !!(parsed.instructions || parsed.accounts || parsed.name);
  } catch {
    return false;
  }
}
