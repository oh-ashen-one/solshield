/**
 * Rust Source Code Parser
 * 
 * Parses Rust source files to extract security-relevant information
 * for pattern matching and vulnerability detection.
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';

export interface ParsedRust {
  functions: FunctionInfo[];
  structs: StructInfo[];
  accounts: AccountInfo[];
  instructions: InstructionInfo[];
  raw: string;
  imports: string[];
  macros: MacroUsage[];
}

export interface FunctionInfo {
  name: string;
  visibility: 'pub' | 'private';
  params: string[];
  returnType: string;
  body: string;
  line: number;
  attributes: string[];
}

export interface StructInfo {
  name: string;
  fields: FieldInfo[];
  attributes: string[];
  line: number;
}

export interface FieldInfo {
  name: string;
  type: string;
  attributes: string[];
}

export interface AccountInfo {
  name: string;
  constraints: string[];
  isMut: boolean;
  isSigner: boolean;
  line: number;
}

export interface InstructionInfo {
  name: string;
  accounts: string[];
  args: string[];
  line: number;
}

export interface MacroUsage {
  name: string;
  args: string;
  line: number;
}

/**
 * Parse a single Rust file
 */
export function parseRustFile(filePath: string): ParsedRust {
  if (!existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }
  
  const content = readFileSync(filePath, 'utf-8');
  return parseRustContent(content);
}

/**
 * Parse Rust source code content
 */
export function parseRustContent(content: string): ParsedRust {
  const lines = content.split('\n');
  
  return {
    functions: extractFunctions(content, lines),
    structs: extractStructs(content, lines),
    accounts: extractAccounts(content, lines),
    instructions: extractInstructions(content, lines),
    raw: content,
    imports: extractImports(content),
    macros: extractMacros(content, lines),
  };
}

/**
 * Parse all Rust files in a directory
 */
export function parseRustFiles(dirPath: string): ParsedRust[] {
  const results: ParsedRust[] = [];
  
  function walkDir(dir: string) {
    if (!existsSync(dir)) return;
    
    const entries = readdirSync(dir);
    for (const entry of entries) {
      const fullPath = join(dir, entry);
      const stat = statSync(fullPath);
      
      if (stat.isDirectory()) {
        // Skip common non-source directories
        if (!['target', 'node_modules', '.git', 'dist'].includes(entry)) {
          walkDir(fullPath);
        }
      } else if (extname(entry) === '.rs') {
        try {
          results.push(parseRustFile(fullPath));
        } catch (e) {
          // Skip files that can't be parsed
        }
      }
    }
  }
  
  walkDir(dirPath);
  return results;
}

function extractFunctions(content: string, lines: string[]): FunctionInfo[] {
  const functions: FunctionInfo[] = [];
  const fnRegex = /(?:(pub(?:\s*\([^)]*\))?)\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)(?:\s*->\s*([^{]+))?\s*\{/g;
  
  let match;
  while ((match = fnRegex.exec(content)) !== null) {
    const lineNum = content.substring(0, match.index).split('\n').length;
    const attrs = extractAttributesAbove(lines, lineNum - 1);
    
    // Find function body
    const bodyStart = match.index + match[0].length;
    const bodyEnd = findMatchingBrace(content, bodyStart - 1);
    const body = bodyEnd > bodyStart ? content.substring(bodyStart, bodyEnd) : '';
    
    functions.push({
      name: match[2],
      visibility: match[1]?.startsWith('pub') ? 'pub' : 'private',
      params: match[3].split(',').map(p => p.trim()).filter(Boolean),
      returnType: match[4]?.trim() || 'void',
      body,
      line: lineNum,
      attributes: attrs,
    });
  }
  
  return functions;
}

function extractStructs(content: string, lines: string[]): StructInfo[] {
  const structs: StructInfo[] = [];
  const structRegex = /(?:pub\s+)?struct\s+(\w+)(?:<[^>]*>)?\s*\{([^}]*)\}/g;
  
  let match;
  while ((match = structRegex.exec(content)) !== null) {
    const lineNum = content.substring(0, match.index).split('\n').length;
    const attrs = extractAttributesAbove(lines, lineNum - 1);
    const fields = extractFields(match[2]);
    
    structs.push({
      name: match[1],
      fields,
      attributes: attrs,
      line: lineNum,
    });
  }
  
  return structs;
}

function extractFields(fieldsStr: string): FieldInfo[] {
  const fields: FieldInfo[] = [];
  const fieldRegex = /(?:#\[([^\]]+)\]\s*)*(?:pub\s+)?(\w+)\s*:\s*([^,\n]+)/g;
  
  let match;
  while ((match = fieldRegex.exec(fieldsStr)) !== null) {
    fields.push({
      name: match[2],
      type: match[3].trim(),
      attributes: match[1] ? [match[1]] : [],
    });
  }
  
  return fields;
}

function extractAccounts(content: string, lines: string[]): AccountInfo[] {
  const accounts: AccountInfo[] = [];
  
  // Match Anchor account constraints
  const accountRegex = /#\[account\(([^)]*)\)\]\s*(?:pub\s+)?(\w+)\s*:/g;
  
  let match;
  while ((match = accountRegex.exec(content)) !== null) {
    const lineNum = content.substring(0, match.index).split('\n').length;
    const constraints = match[1].split(',').map(c => c.trim()).filter(Boolean);
    
    accounts.push({
      name: match[2],
      constraints,
      isMut: constraints.some(c => c.includes('mut')),
      isSigner: constraints.some(c => c.includes('signer')),
      line: lineNum,
    });
  }
  
  return accounts;
}

function extractInstructions(content: string, lines: string[]): InstructionInfo[] {
  const instructions: InstructionInfo[] = [];
  
  // Match Anchor instruction handlers
  const instrRegex = /#\[instruction\(([^)]*)\)\]/g;
  
  let match;
  while ((match = instrRegex.exec(content)) !== null) {
    const lineNum = content.substring(0, match.index).split('\n').length;
    
    instructions.push({
      name: `instruction_${instructions.length}`,
      accounts: [],
      args: match[1].split(',').map(a => a.trim()).filter(Boolean),
      line: lineNum,
    });
  }
  
  return instructions;
}

function extractImports(content: string): string[] {
  const imports: string[] = [];
  const useRegex = /use\s+([^;]+);/g;
  
  let match;
  while ((match = useRegex.exec(content)) !== null) {
    imports.push(match[1].trim());
  }
  
  return imports;
}

function extractMacros(content: string, lines: string[]): MacroUsage[] {
  const macros: MacroUsage[] = [];
  const macroRegex = /(\w+)!\s*(?:\(([^)]*)\)|\{([^}]*)\}|\[([^\]]*)\])/g;
  
  let match;
  while ((match = macroRegex.exec(content)) !== null) {
    const lineNum = content.substring(0, match.index).split('\n').length;
    
    macros.push({
      name: match[1],
      args: match[2] || match[3] || match[4] || '',
      line: lineNum,
    });
  }
  
  return macros;
}

function extractAttributesAbove(lines: string[], lineIndex: number): string[] {
  const attrs: string[] = [];
  let i = lineIndex - 1;
  
  while (i >= 0 && lines[i].trim().startsWith('#[')) {
    const match = lines[i].match(/#\[([^\]]+)\]/);
    if (match) {
      attrs.unshift(match[1]);
    }
    i--;
  }
  
  return attrs;
}

function findMatchingBrace(content: string, startIndex: number): number {
  let depth = 1;
  let i = startIndex + 1;
  
  while (i < content.length && depth > 0) {
    if (content[i] === '{') depth++;
    else if (content[i] === '}') depth--;
    i++;
  }
  
  return depth === 0 ? i - 1 : -1;
}
