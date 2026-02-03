// src/parsers/idl.ts
import { readFileSync } from "fs";
async function parseIdl(idlPath) {
  const content = readFileSync(idlPath, "utf-8");
  const idl = JSON.parse(content);
  const instructions = (idl.instructions || []).map((ix) => ({
    name: ix.name,
    accounts: (ix.accounts || []).map((acc) => ({
      name: acc.name,
      isMut: acc.isMut ?? acc.writable ?? false,
      isSigner: acc.isSigner ?? acc.signer ?? false,
      isOptional: acc.isOptional ?? false,
      pda: acc.pda
    })),
    args: (ix.args || []).map((arg) => ({
      name: arg.name,
      type: arg.type
    }))
  }));
  const accounts = (idl.accounts || []).map((acc) => ({
    name: acc.name,
    type: acc.type
  }));
  const types = (idl.types || []).map((t) => ({
    name: t.name,
    type: t.type
  }));
  const errors = (idl.errors || []).map((e) => ({
    code: e.code,
    name: e.name,
    msg: e.msg
  }));
  return {
    name: idl.name || idl.metadata?.name || "unknown",
    version: idl.version || idl.metadata?.version || "0.0.0",
    instructions,
    accounts,
    types,
    errors,
    metadata: idl.metadata
  };
}
function getAccountsWithoutSigner(idl) {
  const results = [];
  for (const ix of idl.instructions) {
    const hasSigner = ix.accounts.some((acc) => acc.isSigner);
    if (!hasSigner && ix.accounts.length > 0) {
      results.push({
        instruction: ix.name,
        account: ix.accounts[0].name
      });
    }
  }
  return results;
}
function getMutableAccountsWithoutOwnerCheck(idl) {
  const results = [];
  for (const ix of idl.instructions) {
    for (const acc of ix.accounts) {
      if (acc.isMut && !acc.pda && !isSystemAccount(acc.name)) {
        results.push({
          instruction: ix.name,
          account: acc.name
        });
      }
    }
  }
  return results;
}
function isSystemAccount(name) {
  const systemAccounts = [
    "system_program",
    "systemProgram",
    "token_program",
    "tokenProgram",
    "rent",
    "clock",
    "associated_token_program",
    "associatedTokenProgram"
  ];
  return systemAccounts.includes(name);
}

export {
  parseIdl,
  getAccountsWithoutSigner,
  getMutableAccountsWithoutOwnerCheck
};
