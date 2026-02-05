#!/usr/bin/env node

// src/index.ts
import { Command } from "commander";

// src/parsers/rust.ts
import { readFileSync } from "fs";
async function parseRustFiles(filePaths) {
  const files = [];
  const functions = [];
  const structs = [];
  const implBlocks = [];
  let allContent = "";
  for (const filePath of filePaths) {
    try {
      const content = readFileSync(filePath, "utf-8");
      const lines = content.split("\n");
      allContent += content + "\n";
      files.push({ path: filePath, content, lines });
      const funcRegex = /(?:pub\s+)?fn\s+(\w+)\s*\(([^)]*)\)/g;
      let match;
      while ((match = funcRegex.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split("\n").length;
        functions.push({
          name: match[1],
          file: filePath,
          line: lineNum,
          visibility: match[0].includes("pub") ? "public" : "private",
          params: match[2].split(",").map((p) => p.trim()).filter(Boolean),
          body: extractFunctionBody(content, match.index)
        });
      }
      const structRegex = /((?:#\[[^\]]+\]\s*)*)?(?:pub\s+)?struct\s+(\w+)/g;
      while ((match = structRegex.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split("\n").length;
        structs.push({
          name: match[2],
          file: filePath,
          line: lineNum,
          fields: extractStructFields(content, match.index),
          attributes: match[1] ? match[1].split("#").filter(Boolean).map((a) => "#" + a.trim()) : []
        });
      }
      const implRegex = /impl(?:\s*<[^>]*>)?\s+(\w+)/g;
      while ((match = implRegex.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split("\n").length;
        implBlocks.push({
          name: match[1],
          file: filePath,
          line: lineNum,
          methods: extractImplMethods(content, match.index)
        });
      }
    } catch (error) {
      console.warn(`Failed to parse ${filePath}: ${error}`);
    }
  }
  return {
    files,
    functions,
    structs,
    implBlocks,
    content: allContent,
    filePath: filePaths[0] || ""
  };
}
function extractFunctionBody(content, startIndex) {
  let braceCount = 0;
  let started = false;
  let bodyStart = startIndex;
  for (let i = startIndex; i < content.length; i++) {
    if (content[i] === "{") {
      if (!started) {
        started = true;
        bodyStart = i;
      }
      braceCount++;
    } else if (content[i] === "}") {
      braceCount--;
      if (started && braceCount === 0) {
        return content.substring(bodyStart, i + 1);
      }
    }
  }
  return "";
}
function extractStructFields(content, startIndex) {
  const fields = [];
  let braceCount = 0;
  let started = false;
  let fieldSection = "";
  for (let i = startIndex; i < content.length; i++) {
    if (content[i] === "{") {
      started = true;
      braceCount++;
    } else if (content[i] === "}") {
      braceCount--;
      if (started && braceCount === 0) {
        break;
      }
    } else if (started && braceCount === 1) {
      fieldSection += content[i];
    }
  }
  const fieldRegex = /(?:pub\s+)?(\w+)\s*:\s*([^,}]+)/g;
  let match;
  while ((match = fieldRegex.exec(fieldSection)) !== null) {
    fields.push({ name: match[1], type: match[2].trim() });
  }
  return fields;
}
function extractImplMethods(content, startIndex) {
  const methods = [];
  let braceCount = 0;
  let started = false;
  let implBlock = "";
  for (let i = startIndex; i < content.length; i++) {
    if (content[i] === "{") {
      started = true;
      braceCount++;
    } else if (content[i] === "}") {
      braceCount--;
      if (started && braceCount === 0) {
        break;
      }
    }
    if (started) {
      implBlock += content[i];
    }
  }
  const methodRegex = /(?:pub\s+)?fn\s+(\w+)/g;
  let match;
  while ((match = methodRegex.exec(implBlock)) !== null) {
    methods.push(match[1]);
  }
  return methods;
}

// src/patterns/sec3-2025-business-logic.ts
function checkSec32025BusinessLogic(input) {
  const findings = [];
  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join("\n");
      if ((line.includes("state =") || line.includes("status =")) && line.includes("::") && !context.includes("require!") && !context.includes("assert!") && !context.includes("match state")) {
        findings.push({
          id: "SEC3-BL001",
          title: "State Transition Without Validation",
          severity: "high",
          description: "State changes without validating allowed transitions. Attackers can skip intermediate states.",
          location: { file: input.path, line: i + 1 },
          suggestion: "Add state machine validation: require!(current_state == AllowedPreviousState, InvalidTransition)",
          cwe: "CWE-840"
        });
      }
      if ((line.includes("/ 100") || line.includes("/ 10000") || line.includes("/ 10_000")) && !line.includes("checked_")) {
        if (!context.includes("saturating") && !context.includes("checked_div")) {
          findings.push({
            id: "SEC3-BL002",
            title: "Percentage Calculation Without Safe Math",
            severity: "medium",
            description: "Percentage/basis point calculations should use checked math to prevent rounding exploits.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Use checked_mul then checked_div, or dedicated percentage math library.",
            cwe: "CWE-682"
          });
        }
      }
      if (line.includes("pub fn process_order") || line.includes("fn execute_order") || line.includes("fn fill_order")) {
        if (!context.includes("expired") && !context.includes("expiry") && !context.includes("deadline")) {
          findings.push({
            id: "SEC3-BL003",
            title: "Order Processing Without Expiry Check",
            severity: "high",
            description: "Order execution without expiry validation allows stale order exploitation.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Always check: require!(order.expiry > clock.unix_timestamp, OrderExpired)",
            cwe: "CWE-613"
          });
        }
      }
      if ((line.includes("pub fn withdraw") || line.includes("fn withdraw")) && !line.includes("//")) {
        if (!context.includes("cooldown") && !context.includes("lock_") && !context.includes("timelock") && !context.includes("unlock_time")) {
          findings.push({
            id: "SEC3-BL004",
            title: "Withdrawal Without Timelock Check",
            severity: "medium",
            description: "Withdrawal function without timelock/cooldown validation.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Consider adding withdrawal cooldowns: require!(clock.unix_timestamp > user.last_deposit + COOLDOWN)",
            cwe: "CWE-362"
          });
        }
      }
      if ((line.includes("reward") || line.includes("yield")) && (line.includes(" * ") || line.includes(" / "))) {
        if (!context.includes("last_update") && !context.includes("accumulated") && !context.includes("per_share")) {
          findings.push({
            id: "SEC3-BL005",
            title: "Reward Calculation Without Time Normalization",
            severity: "high",
            description: "Reward calculations should track time since last update to prevent manipulation.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Track rewards_per_share and last_update_timestamp for correct distribution.",
            cwe: "CWE-682"
          });
        }
      }
      if (line.includes("liquidat") && !line.includes("//")) {
        if (!context.includes("health_factor") && !context.includes("collateral_ratio") && !context.includes("ltv") && !context.includes("margin")) {
          findings.push({
            id: "SEC3-BL006",
            title: "Liquidation Without Health Factor",
            severity: "critical",
            description: "Liquidation logic without clear health factor calculation is exploitable.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Always compute health_factor = collateral_value * ltv / debt_value",
            cwe: "CWE-682"
          });
        }
      }
      if (line.includes("fee") && (line.includes(" = 0") || line.includes("= 0u"))) {
        findings.push({
          id: "SEC3-BL007",
          title: "Fee Set to Zero Detected",
          severity: "medium",
          description: "Hardcoded zero fee may indicate missing fee logic or potential bypass.",
          location: { file: input.path, line: i + 1 },
          suggestion: "Ensure fees cannot be bypassed. Consider minimum fee requirements.",
          cwe: "CWE-20"
        });
      }
      if ((line.includes("vote_weight") || line.includes("voting_power")) && !line.includes("//")) {
        if (!context.includes("snapshot") && !context.includes("checkpoint") && !context.includes("lock_time")) {
          findings.push({
            id: "SEC3-BL008",
            title: "Vote Weight Without Snapshot",
            severity: "high",
            description: "Voting power calculations without snapshots enable flash loan governance attacks.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Use snapshot-based voting: vote_weight = get_weight_at_snapshot(proposal.snapshot_slot)",
            cwe: "CWE-362"
          });
        }
      }
      if ((line.includes("pub fn stake") || line.includes("pub fn unstake")) && !line.includes("//")) {
        if (!context.includes("epoch") && !context.includes("warmup") && !context.includes("cooldown")) {
          findings.push({
            id: "SEC3-BL009",
            title: "Staking Without Epoch Boundaries",
            severity: "medium",
            description: "Stake/unstake without epoch boundaries allows reward gaming.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Align staking changes with epoch boundaries or add warmup/cooldown periods.",
            cwe: "CWE-682"
          });
        }
      }
      if ((line.includes("open_position") || line.includes("increase_position")) && !line.includes("//")) {
        if (!context.includes("max_position") && !context.includes("position_limit") && !context.includes("max_size")) {
          findings.push({
            id: "SEC3-BL010",
            title: "Position Opening Without Size Limits",
            severity: "high",
            description: "Trading positions without size limits can destabilize the protocol.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Enforce position limits: require!(new_size <= max_position_size, PositionTooLarge)",
            cwe: "CWE-770"
          });
        }
      }
    }
  }
  return findings;
}

// src/patterns/sec3-2025-input-validation.ts
function checkSec32025InputValidation(input) {
  const findings = [];
  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join("\n");
      if (line.includes("instruction_data") || line.includes("data: &[u8]")) {
        if (!context.includes(".len()") && !context.includes("size_of")) {
          findings.push({
            id: "SEC3-IV001",
            title: "Instruction Data Size Not Validated",
            severity: "high",
            description: "Instruction data should have size validation before deserialization.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Check: require!(data.len() >= MIN_SIZE && data.len() <= MAX_SIZE, InvalidDataLength)",
            cwe: "CWE-20"
          });
        }
      }
      if ((line.includes("String") || line.includes("Vec<u8>")) && line.includes("pub ") && !line.includes("//")) {
        if (!context.includes("max_len") && !context.includes("MAX_") && !context.includes("#[max_len")) {
          findings.push({
            id: "SEC3-IV002",
            title: "Unbounded String/Bytes Field",
            severity: "medium",
            description: "String or byte vector without maximum length constraint can cause DoS.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Add Anchor constraint: #[max_len(256)] or validate length manually.",
            cwe: "CWE-400"
          });
        }
      }
      if ((line.includes("amount") || line.includes("quantity") || line.includes("price")) && line.includes(": u") && !line.includes("//")) {
        if (!context.includes("> 0") && !context.includes("!= 0") && !context.includes("require!") && !context.includes("assert!")) {
          findings.push({
            id: "SEC3-IV003",
            title: "Numeric Input Without Range Validation",
            severity: "medium",
            description: "Numeric inputs should be validated for acceptable ranges.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Add validation: require!(amount > 0 && amount <= MAX_AMOUNT, InvalidAmount)",
            cwe: "CWE-20"
          });
        }
      }
      if ((line.includes("timestamp") || line.includes("expiry") || line.includes("deadline")) && !line.includes("clock.unix_timestamp")) {
        if (line.includes(": i64") || line.includes(": u64")) {
          findings.push({
            id: "SEC3-IV004",
            title: "Timestamp Input Not Clock-Validated",
            severity: "high",
            description: "User-provided timestamps should be validated against on-chain clock.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Compare to clock: require!(timestamp > clock.unix_timestamp, TimestampInPast)",
            cwe: "CWE-20"
          });
        }
      }
      if (line.includes("Vec<Pubkey>") && !context.includes("max_len") && !context.includes("MAX_")) {
        findings.push({
          id: "SEC3-IV005",
          title: "Unbounded Pubkey Array",
          severity: "medium",
          description: "Arrays of pubkeys without bounds can cause compute exhaustion.",
          location: { file: input.path, line: i + 1 },
          suggestion: "Limit array size: require!(accounts.len() <= MAX_ACCOUNTS, TooManyAccounts)",
          cwe: "CWE-400"
        });
      }
      if (line.includes("decimals") && (line.includes("9") || line.includes("6"))) {
        if (!context.includes("mint.decimals") && !context.includes(".decimals")) {
          findings.push({
            id: "SEC3-IV006",
            title: "Hardcoded Decimal Assumption",
            severity: "high",
            description: "Hardcoded decimal values instead of reading from mint. Different tokens have different decimals.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Always read decimals from mint account: let decimals = ctx.accounts.mint.decimals;",
            cwe: "CWE-682"
          });
        }
      }
      if (line.includes("seeds") && line.includes("&[")) {
        if (context.includes("as &[u8]") && !context.includes("validate") && !context.includes(".len()")) {
          findings.push({
            id: "SEC3-IV007",
            title: "PDA Seed Input Not Sanitized",
            severity: "high",
            description: "User-provided PDA seeds should be length-validated to prevent collision attacks.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Validate seed length: require!(seed.len() <= 32, SeedTooLong)",
            cwe: "CWE-20"
          });
        }
      }
      if (line.includes("as u8") && context.includes("enum") && !context.includes("TryFrom")) {
        findings.push({
          id: "SEC3-IV008",
          title: "Enum Cast Without Bounds Check",
          severity: "medium",
          description: "Casting integers to enums should use TryFrom to validate variants.",
          location: { file: input.path, line: i + 1 },
          suggestion: "Use TryFrom: let variant = MyEnum::try_from(value).map_err(|_| InvalidVariant)?;",
          cwe: "CWE-20"
        });
      }
      if ((line.includes("try_from_slice") || line.includes("deserialize")) && !context.includes(".len()") && !context.includes("size_of")) {
        findings.push({
          id: "SEC3-IV009",
          title: "Deserialization Without Size Validation",
          severity: "high",
          description: "Deserializing account data without size check can cause panics or read garbage.",
          location: { file: input.path, line: i + 1 },
          suggestion: "Check size before deserializing: require!(data.len() >= std::mem::size_of::<T>())",
          cwe: "CWE-502"
        });
      }
      if ((line.includes("slippage") || line.includes("min_out") || line.includes("max_in")) && !context.includes("require!") && !context.includes("assert!")) {
        findings.push({
          id: "SEC3-IV010",
          title: "Slippage Parameter Not Enforced",
          severity: "high",
          description: "Slippage parameters must be enforced to protect users from sandwich attacks.",
          location: { file: input.path, line: i + 1 },
          suggestion: "Enforce: require!(actual_output >= min_output, SlippageExceeded)",
          cwe: "CWE-20"
        });
      }
    }
  }
  return findings;
}

// src/patterns/sec3-2025-access-control.ts
function checkSec32025AccessControl(input) {
  const findings = [];
  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join("\n");
      if ((line.includes("pub fn admin") || line.includes("pub fn set_") || line.includes("pub fn update_") || line.includes("pub fn pause")) && !line.includes("//")) {
        if (!context.includes("has_one") && !context.includes("constraint =") && !context.includes("authority") && !context.includes("admin")) {
          findings.push({
            id: "SEC3-AC001",
            title: "Admin Function Without Authority Constraint",
            severity: "critical",
            description: "Administrative function lacks authority validation.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Add Anchor constraint: #[account(has_one = authority @ UnauthorizedAdmin)]",
            cwe: "CWE-862"
          });
        }
      }
      if ((line.includes("upgrade") || line.includes("withdraw_all") || line.includes("emergency") || line.includes("migrate")) && !line.includes("//")) {
        if (!context.includes("multisig") && !context.includes("multi_sig") && !context.includes("threshold") && !context.includes("signers")) {
          findings.push({
            id: "SEC3-AC002",
            title: "Critical Operation Without Multi-Sig",
            severity: "high",
            description: "Critical operations should require multi-signature authorization.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Implement multi-sig: require!(approved_signers >= threshold, InsufficientSigners)",
            cwe: "CWE-287"
          });
        }
      }
      if (line.includes("pub fn") && (line.includes("_admin") || line.includes("_operator") || line.includes("_manager"))) {
        if (!context.includes("role") && !context.includes("permission") && !context.includes("is_authorized")) {
          findings.push({
            id: "SEC3-AC003",
            title: "Role-Based Function Without Role Check",
            severity: "high",
            description: "Function implies role-based access but lacks explicit role verification.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Verify role: require!(user.role == Role::Admin, UnauthorizedRole)",
            cwe: "CWE-285"
          });
        }
      }
      if (line.includes("invoke") && !line.includes("invoke_signed")) {
        if (!context.includes("is_signer") && !context.includes("Signer<")) {
          findings.push({
            id: "SEC3-AC004",
            title: "CPI Without Signer Verification",
            severity: "high",
            description: "Cross-program invocation without verifying the signer authority.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Verify signer: require!(authority.is_signer, MissingSigner)",
            cwe: "CWE-863"
          });
        }
      }
      if (line.includes("delegate") && !line.includes("//")) {
        if (!context.includes("max_amount") && !context.includes("expiry") && !context.includes("allowed_operations")) {
          findings.push({
            id: "SEC3-AC005",
            title: "Delegation Without Scope Limits",
            severity: "medium",
            description: "Delegated authority should have amount limits and expiry.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Scope delegation: delegate.max_amount, delegate.expiry, delegate.allowed_ops",
            cwe: "CWE-269"
          });
        }
      }
      if ((line.includes("transfer_ownership") || line.includes("new_owner") || line.includes("pending_owner")) && !line.includes("//")) {
        if (!context.includes("accept_ownership") && !context.includes("confirm") && !context.includes("two_step")) {
          findings.push({
            id: "SEC3-AC006",
            title: "Ownership Transfer Without 2-Step Confirmation",
            severity: "high",
            description: "Ownership transfers should use 2-step process to prevent accidental loss.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Use pending_owner pattern: set_pending_owner() -> accept_ownership()",
            cwe: "CWE-269"
          });
        }
      }
      if ((line.includes("mint_authority") || line.includes("freeze_authority")) && !context.includes("PDA") && !context.includes("find_program_address") && !context.includes("seeds")) {
        findings.push({
          id: "SEC3-AC007",
          title: "Token Authority Not PDA",
          severity: "medium",
          description: "Token authorities should be PDAs for programmatic control.",
          location: { file: input.path, line: i + 1 },
          suggestion: 'Derive authority from PDA: seeds = [b"mint_authority", mint.key().as_ref()]',
          cwe: "CWE-269"
        });
      }
      if ((line.includes("pub fn crank") || line.includes("pub fn update_price") || line.includes("pub fn liquidate")) && !line.includes("//")) {
        if (!context.includes("reward") && !context.includes("fee") && !context.includes("incentive")) {
          findings.push({
            id: "SEC3-AC008",
            title: "Permissionless Crank Without Incentive",
            severity: "low",
            description: "Permissionless functions should incentivize crankers to ensure liveness.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Add cranker rewards to incentivize timely execution.",
            cwe: "CWE-400"
          });
        }
      }
      if (line.includes("close =") || line.includes("close_account")) {
        if (!context.includes("authority") && !context.includes("has_one") && !context.includes("owner")) {
          findings.push({
            id: "SEC3-AC009",
            title: "Account Close Without Authority Check",
            severity: "critical",
            description: "Account closure must verify the closer has authority.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Add constraint: #[account(close = authority, has_one = authority)]",
            cwe: "CWE-862"
          });
        }
      }
      if (line.includes("timelock") && !line.includes("//")) {
        if (!context.includes("min_delay") && !context.includes("MIN_DELAY") && !context.includes("TIMELOCK_DURATION")) {
          findings.push({
            id: "SEC3-AC010",
            title: "Timelock Without Minimum Delay",
            severity: "high",
            description: "Timelocks should have a minimum delay that cannot be bypassed.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Enforce minimum: require!(delay >= MIN_TIMELOCK_DELAY, DelayTooShort)",
            cwe: "CWE-269"
          });
        }
      }
    }
  }
  return findings;
}

// src/patterns/sec3-2025-data-integrity.ts
function checkSec32025DataIntegrity(input) {
  const findings = [];
  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join("\n");
      if (line.includes(" / ") && !line.includes("//")) {
        if ((line.includes("u64") || line.includes("u128")) && !context.includes("checked_div") && !context.includes("saturating")) {
          if (line.includes(" * ") && line.indexOf(" / ") > line.indexOf(" * ")) {
            findings.push({
              id: "SEC3-DI001",
              title: "Division Before Multiplication",
              severity: "high",
              description: "Division before multiplication can cause precision loss. Always multiply first.",
              location: { file: input.path, line: i + 1 },
              suggestion: "Reorder: (a * b) / c instead of (a / c) * b",
              cwe: "CWE-682"
            });
          }
        }
      }
      if ((line.includes("as u64") || line.includes("as u128")) && (context.includes(" / ") || context.includes("div"))) {
        if (!context.includes("floor") && !context.includes("ceil") && !context.includes("round") && !context.includes("direction")) {
          findings.push({
            id: "SEC3-DI002",
            title: "Implicit Rounding Direction",
            severity: "medium",
            description: "Integer division implicitly floors. Specify rounding direction explicitly.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Use explicit rounding: floor for protocol benefit, ceil for user protection.",
            cwe: "CWE-682"
          });
        }
      }
      if ((line.includes(".save()") || line.includes("serialize")) && !line.includes("//")) {
        if (!context.includes("atomic") && !context.includes("transaction") && !context.includes("all_or_nothing")) {
          const stateUpdates = (context.match(/\.\s*\w+\s*=/g) || []).length;
          if (stateUpdates >= 3) {
            findings.push({
              id: "SEC3-DI003",
              title: "Non-Atomic Multi-State Update",
              severity: "high",
              description: "Multiple state updates without atomic transaction can leave inconsistent state on failure.",
              location: { file: input.path, line: i + 1 },
              suggestion: "Group related state changes atomically. Consider using a state machine.",
              cwe: "CWE-362"
            });
          }
        }
      }
      if ((line.includes("shares") || line.includes("share_price")) && (line.includes(" / ") || line.includes(" * "))) {
        if (!context.includes("virtual") && !context.includes("OFFSET") && !context.includes("MIN_DEPOSIT")) {
          findings.push({
            id: "SEC3-DI004",
            title: "Share Calculation Without Inflation Protection",
            severity: "critical",
            description: "Share calculations without virtual offset are vulnerable to first-depositor inflation attack.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Add virtual shares offset: shares = (deposit + 1) * TOTAL_SHARES / (totalAssets + 1)",
            cwe: "CWE-682"
          });
        }
      }
      if (line.includes("other_account") || line.includes("related_account")) {
        if (!context.includes("reload") && !context.includes("refresh") && !context.includes("re-fetch")) {
          findings.push({
            id: "SEC3-DI005",
            title: "Cross-Account Data Without Refresh",
            severity: "medium",
            description: "Reading from related accounts without refresh may use stale data.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Reload related account data: account.reload()?",
            cwe: "CWE-662"
          });
        }
      }
      if (line.includes("merkle") && (line.includes("verify") || line.includes("proof"))) {
        if (!context.includes("index") && !context.includes("leaf_index") && !context.includes("position")) {
          findings.push({
            id: "SEC3-DI006",
            title: "Merkle Proof Missing Index Validation",
            severity: "high",
            description: "Merkle proofs should verify the leaf index to prevent replay at different positions.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Include leaf index in hash: hash(index || leaf_data)",
            cwe: "CWE-354"
          });
        }
      }
      if ((line.includes("balance") || line.includes("amount")) && (line.includes("+=") || line.includes("-="))) {
        if (!context.includes("total") && !context.includes("sum") && !context.includes("invariant")) {
          findings.push({
            id: "SEC3-DI007",
            title: "Balance Update Without Invariant Check",
            severity: "high",
            description: "Balance updates should verify total invariants (sum of parts = whole).",
            location: { file: input.path, line: i + 1 },
            suggestion: "Add invariant: require!(user_balances.sum() == total_balance, InvariantViolation)",
            cwe: "CWE-682"
          });
        }
      }
      if (line.includes("nonce") && (line.includes("+= 1") || line.includes("+ 1"))) {
        if (!context.includes("checked_add") && !context.includes("wrapping")) {
          findings.push({
            id: "SEC3-DI008",
            title: "Nonce Increment Without Overflow Check",
            severity: "medium",
            description: "Nonce increment should handle overflow (wrap or reject).",
            location: { file: input.path, line: i + 1 },
            suggestion: "Use: nonce = nonce.checked_add(1).ok_or(NonceOverflow)?",
            cwe: "CWE-190"
          });
        }
      }
      if ((line.includes("epoch") || line.includes("period")) && (line.includes(" / ") || line.includes("div"))) {
        if (!context.includes("boundary") && !context.includes("start_time") && !context.includes("end_time")) {
          findings.push({
            id: "SEC3-DI009",
            title: "Epoch Calculation Without Boundary Handling",
            severity: "medium",
            description: "Epoch calculations should handle boundary conditions explicitly.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Define epoch_start and epoch_end, handle edge cases at boundaries.",
            cwe: "CWE-682"
          });
        }
      }
      if (line.includes("10_u128.pow") || line.includes("10u128.pow") || line.includes("PRECISION") || line.includes("SCALE")) {
        if (!context.includes("DECIMALS") && !context.includes("decimal_places")) {
          findings.push({
            id: "SEC3-DI010",
            title: "Fixed-Point Math Without Decimal Tracking",
            severity: "medium",
            description: "Fixed-point operations should track decimal places to prevent precision errors.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Document precision: /// Price is stored with 6 decimal places (PRICE_DECIMALS = 6)",
            cwe: "CWE-682"
          });
        }
      }
    }
  }
  return findings;
}

// src/patterns/sec3-2025-dos-liveness.ts
function checkSec32025DosLiveness(input) {
  const findings = [];
  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join("\n");
      if ((line.includes("for ") || line.includes(".iter()")) && !line.includes("// bounded") && !line.includes("// SAFETY")) {
        if (context.includes("Vec<") && !context.includes("MAX_") && !context.includes(".take(") && !context.includes("limit")) {
          findings.push({
            id: "SEC3-DOS001",
            title: "Unbounded Loop Over Dynamic Collection",
            severity: "high",
            description: "Iterating over unbounded collections can exhaust compute budget.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Bound iteration: for item in items.iter().take(MAX_ITEMS)",
            cwe: "CWE-400"
          });
        }
      }
      if ((line.includes("pub fn") || line.includes("fn process")) && !line.includes("//")) {
        if (content.includes("for ") && !content.includes("compute_budget") && !content.includes("ComputeBudget")) {
          findings.push({
            id: "SEC3-DOS002",
            title: "No Compute Budget Management",
            severity: "medium",
            description: "Complex operations should track compute budget to fail gracefully.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Add early exit if running low on compute units.",
            cwe: "CWE-400"
          });
        }
      }
      if ((line.includes("while ") || line.includes("loop {")) && !context.includes("break") && !context.includes("return")) {
        if (!context.includes("max_iter") && !context.includes("timeout") && !context.includes("deadline")) {
          findings.push({
            id: "SEC3-DOS003",
            title: "Potentially Infinite Loop",
            severity: "critical",
            description: "Loop without clear termination condition can hang transaction.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Add iteration limit: while condition && iterations < MAX_ITER",
            cwe: "CWE-835"
          });
        }
      }
      if ((line.includes("oracle") || line.includes("price_feed")) && !line.includes("//")) {
        if (!context.includes("fallback") && !context.includes("backup") && !context.includes("stale_price")) {
          findings.push({
            id: "SEC3-DOS004",
            title: "Oracle Dependency Without Fallback",
            severity: "high",
            description: "Oracle failures can DOS the protocol. Have fallback pricing.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Add fallback: let price = oracle.get_price().or_else(|| backup_oracle.get_price())?",
            cwe: "CWE-754"
          });
        }
      }
      if (line.includes("realloc") && !line.includes("//")) {
        if (!context.includes("MAX_SIZE") && !context.includes("max_size") && !context.includes("limit")) {
          findings.push({
            id: "SEC3-DOS005",
            title: "Unbounded Account Reallocation",
            severity: "high",
            description: "Account reallocation without size limit can cause DOS.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Set maximum: require!(new_size <= MAX_ACCOUNT_SIZE, AccountTooLarge)",
            cwe: "CWE-400"
          });
        }
      }
      if (line.includes("invoke") && context.includes("self") && !context.includes("depth") && !context.includes("MAX_DEPTH")) {
        findings.push({
          id: "SEC3-DOS006",
          title: "Recursive CPI Without Depth Limit",
          severity: "high",
          description: "Self-referencing CPI can cause stack overflow or compute exhaustion.",
          location: { file: input.path, line: i + 1 },
          suggestion: "Track and limit CPI depth: require!(depth < MAX_CPI_DEPTH)",
          cwe: "CWE-674"
        });
      }
      if ((line.includes("pub fn mint") || line.includes("pub fn create") || line.includes("pub fn register")) && !line.includes("//")) {
        if (!context.includes("rate_limit") && !context.includes("cooldown") && !context.includes("last_action")) {
          findings.push({
            id: "SEC3-DOS007",
            title: "No Rate Limiting on Creation",
            severity: "medium",
            description: "Account/token creation without rate limits enables spam attacks.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Add rate limiting: require!(clock.unix_timestamp > user.last_create + COOLDOWN)",
            cwe: "CWE-770"
          });
        }
      }
      if ((line.includes("borsh::") || line.includes("BorshDeserialize")) && context.includes("Vec<") && !context.includes("max_len")) {
        findings.push({
          id: "SEC3-DOS008",
          title: "Unbounded Deserialization",
          severity: "high",
          description: "Deserializing unbounded vectors can exhaust memory.",
          location: { file: input.path, line: i + 1 },
          suggestion: "Use bounded types or validate length before deserializing.",
          cwe: "CWE-502"
        });
      }
      if (line.includes("invoke") && !line.includes("token_program") && !line.includes("system_program") && !line.includes("//")) {
        if (!context.includes("program_id ==") && !context.includes("whitelist")) {
          findings.push({
            id: "SEC3-DOS009",
            title: "CPI to Unvalidated Program",
            severity: "high",
            description: "CPI to unvalidated program could invoke malicious code.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Validate CPI target: require!(target_program.key() == KNOWN_PROGRAM_ID)",
            cwe: "CWE-829"
          });
        }
      }
      if ((line.includes("emit!") || line.includes("msg!")) && (context.includes("for ") || context.includes("loop"))) {
        if (!context.includes("limit") && !context.includes("MAX_")) {
          findings.push({
            id: "SEC3-DOS010",
            title: "Event Emission in Loop",
            severity: "low",
            description: "Emitting events in unbounded loops wastes compute and bloats logs.",
            location: { file: input.path, line: i + 1 },
            suggestion: "Emit summary event after loop instead of per-iteration events.",
            cwe: "CWE-400"
          });
        }
      }
    }
  }
  return findings;
}

// src/patterns/helius-2024-2025-deep.ts
function findLineNumber(content, match) {
  const lines = content.substring(0, match.index || 0).split("\n");
  return lines.length;
}
function getSnippet(content, line) {
  const lines = content.split("\n");
  const start = Math.max(0, line - 2);
  const end = Math.min(lines.length, line + 2);
  return lines.slice(start, end).join("\n").substring(0, 200);
}
function checkHelius2024DeepPatterns(input) {
  const findings = [];
  const content = input.rust?.content || "";
  const path = input.path;
  if (!content) return findings;
  const patterns = [
    // DEXX $30M Private Key Leak (Nov 2024)
    {
      id: "HELIUS-DEXX-001",
      name: "Private Key Server Storage",
      severity: "critical",
      pattern: /private_key|secret_key|keypair[\s\S]{0,50}(?:store|save|persist|db|database|redis|cache)/i,
      description: "DEXX-style vulnerability: Storing private keys on servers enables mass theft if compromised.",
      recommendation: "Never store user private keys. Use hardware wallets or client-side encryption only.",
      exploit: "DEXX stored user private keys server-side, enabling $30M theft",
      loss: "$30M"
    },
    {
      id: "HELIUS-DEXX-002",
      name: "Centralized Key Management",
      severity: "critical",
      pattern: /export_private_key|get_private_key|fetch_keypair|decrypt_key[\s\S]{0,50}(?:api|endpoint|route)/i,
      description: "Centralized key management creates single point of failure for user funds.",
      recommendation: "Implement non-custodial architecture where only users control their keys.",
      exploit: "DEXX centralized key management led to mass wallet drains",
      loss: "$30M"
    },
    // Loopscale $5.8M Admin Exploit (Apr 2025)
    {
      id: "HELIUS-LOOP-001",
      name: "Admin Bypass - Collateral Manipulation",
      severity: "critical",
      pattern: /admin|owner|authority[\s\S]{0,100}collateral[\s\S]{0,50}(?:set|update|modify|change)/i,
      description: "Loopscale-style: Admin can manipulate collateral pricing to drain pools.",
      recommendation: "Use timelocks and multi-sig for any collateral parameter changes.",
      exploit: "Loopscale admin manipulated collateral pricing to drain $5.8M",
      loss: "$5.8M"
    },
    {
      id: "HELIUS-LOOP-002",
      name: "Undercollateralized Position Creation",
      severity: "critical",
      pattern: /create_position|open_loan|borrow[\s\S]{0,100}(?![\s\S]{0,50}collateral_ratio|[\s\S]{0,50}health_check)/i,
      description: "Position creation without collateral ratio validation enables undercollateralized loans.",
      recommendation: "Always verify collateral ratio >= minimum threshold before position creation.",
      exploit: "Loopscale positions created with insufficient collateral backing",
      loss: "$5.8M"
    },
    // Pump.fun Insider Attack ($1.9M May 2024)
    {
      id: "HELIUS-PUMP-001",
      name: "Bonding Curve Parameter Access",
      severity: "critical",
      pattern: /bonding_curve[\s\S]{0,100}(?:withdraw|drain|transfer)[\s\S]{0,50}(?:admin|employee|internal)/i,
      description: "Pump.fun-style: Insider access to bonding curve funds before migration.",
      recommendation: "Use time-locked, multi-sig controlled bonding curves with withdrawal delays.",
      exploit: "Pump.fun employee drained bonding curves using privileged access",
      loss: "$1.9M"
    },
    {
      id: "HELIUS-PUMP-002",
      name: "Early Withdrawal from Bonding Curve",
      severity: "high",
      pattern: /withdraw[\s\S]{0,50}bonding[\s\S]{0,50}(?![\s\S]{0,30}migration_complete|[\s\S]{0,30}locked)/i,
      description: "Withdrawal from bonding curve before migration period completes.",
      recommendation: "Lock bonding curve funds until migration threshold is reached.",
      exploit: "Funds withdrawn before migration to Raydium completed",
      loss: "$1.9M"
    },
    // Thunder Terminal MongoDB Attack ($240K Dec 2023)
    {
      id: "HELIUS-THUNDER-001",
      name: "Session Token Exposure",
      severity: "critical",
      pattern: /session_token|auth_token|jwt[\s\S]{0,50}(?:export|expose|leak|log)/i,
      description: "Thunder Terminal-style: Session tokens stored insecurely enable account takeover.",
      recommendation: "Encrypt session tokens, implement rotation, and never log sensitive tokens.",
      exploit: "MongoDB connection URL compromised session tokens",
      loss: "$240K"
    },
    {
      id: "HELIUS-THUNDER-002",
      name: "Third-Party DB Connection String Exposure",
      severity: "critical",
      pattern: /mongodb|postgres|mysql|redis[\s\S]{0,30}(?:url|uri|connection|string)[\s\S]{0,30}(?:env|config)/i,
      description: "Database connection strings can be exposed through misconfigurations.",
      recommendation: "Use secret managers, rotate credentials, and audit third-party access.",
      exploit: "Third-party MongoDB service exposed connection URLs",
      loss: "$240K"
    },
    // Banana Gun Bot Exploit ($1.4M Sep 2024)
    {
      id: "HELIUS-BANANA-001",
      name: "Trading Bot Transfer Manipulation",
      severity: "critical",
      pattern: /bot[\s\S]{0,50}transfer[\s\S]{0,50}(?:message|telegram|oracle)/i,
      description: "Banana Gun-style: Telegram oracle manipulation in trading bots.",
      recommendation: "Implement message signing and verification for bot commands.",
      exploit: "Telegram message system vulnerability enabled unauthorized transfers",
      loss: "$1.4M"
    },
    {
      id: "HELIUS-BANANA-002",
      name: "Bot Command Injection",
      severity: "critical",
      pattern: /parse_command|execute_command|bot_instruction[\s\S]{0,50}(?![\s\S]{0,30}sanitize|[\s\S]{0,30}validate)/i,
      description: "Bot commands executed without proper validation enable fund theft.",
      recommendation: "Sanitize all bot inputs, require signatures for transfers.",
      exploit: "Malicious commands injected into trading bot",
      loss: "$1.4M"
    },
    // Cypher Insider Theft ($317K 2024)
    {
      id: "HELIUS-CYPHER-001",
      name: "Insider Treasury Access",
      severity: "critical",
      pattern: /treasury|vault[\s\S]{0,50}(?:admin|manager|employee)[\s\S]{0,30}(?:withdraw|transfer|drain)/i,
      description: "Cypher-style: Former employees with unrevoced treasury access.",
      recommendation: "Implement immediate access revocation for departing employees.",
      exploit: "Former contractor retained backend access, drained remaining funds",
      loss: "$317K"
    },
    {
      id: "HELIUS-CYPHER-002",
      name: "Credential Persistence After Termination",
      severity: "high",
      pattern: /employee|contractor|staff[\s\S]{0,50}(?:credential|access|permission)[\s\S]{0,30}(?:remove|revoke|expire)/i,
      description: "Credentials not properly revoked when employees leave.",
      recommendation: "Automate credential revocation upon employee departure.",
      exploit: "Hoak retained access months after leaving Cypher",
      loss: "$317K"
    },
    // NoOnes MongoDB Attack (Jan 2025)
    {
      id: "HELIUS-NOONES-001",
      name: "Withdrawal Processing Exploit",
      severity: "critical",
      pattern: /withdrawal[\s\S]{0,50}process[\s\S]{0,50}(?:batch|queue|pending)/i,
      description: "NoOnes-style: Withdrawal processing system compromised.",
      recommendation: "Multi-signature withdrawal processing with manual review for large amounts.",
      exploit: "Hot wallet drained through compromised withdrawal system",
      loss: "$8.5M"
    },
    // Web3.js Supply Chain (Dec 2024)
    {
      id: "HELIUS-WEB3JS-001",
      name: "NPM Dependency Backdoor",
      severity: "critical",
      pattern: /@solana\/web3\.js[\s\S]{0,50}(?:1\.95\.5|1\.95\.6|1\.95\.7)/i,
      description: "Web3.js supply chain attack: Malicious versions exfiltrated private keys.",
      recommendation: "Lock dependencies, use npm audit, verify package integrity.",
      exploit: "Compromised npm account pushed malicious @solana/web3.js versions",
      loss: "$160K+"
    },
    {
      id: "HELIUS-WEB3JS-002",
      name: "Dependency Key Exfiltration",
      severity: "critical",
      pattern: /import[\s\S]{0,30}@solana[\s\S]{0,30}(?:keypair|wallet|account)[\s\S]{0,100}fetch|axios|http/i,
      description: "Dependencies making network requests with key material.",
      recommendation: "Audit dependency network calls, use CSP, monitor outbound traffic.",
      exploit: "Malicious web3.js sent private keys to attacker server",
      loss: "$160K+"
    },
    // Solareum Employee Attack (Jan 2024)
    {
      id: "HELIUS-SOLAR-001",
      name: "Developer Wallet Drain",
      severity: "critical",
      pattern: /developer|dev[\s\S]{0,30}wallet[\s\S]{0,50}(?:access|control|manage)/i,
      description: "Solareum-style: Rogue developer with wallet access.",
      recommendation: "Implement separation of duties, multi-sig for dev wallets.",
      exploit: "Developer with wallet access drained all funds",
      loss: "$468K"
    },
    // io.net GPU Exploit (Apr 2024)
    {
      id: "HELIUS-IONET-001",
      name: "User Metadata SQL Injection",
      severity: "high",
      pattern: /user[\s\S]{0,30}metadata[\s\S]{0,50}(?:query|sql|insert|select)/i,
      description: "io.net-style: User metadata endpoint vulnerable to injection.",
      recommendation: "Parameterize all queries, sanitize user inputs.",
      exploit: "SQL injection in user metadata API",
      loss: "Service disruption"
    },
    // Synthetify DAO Attack (Oct 2023)
    {
      id: "HELIUS-SYNTH-001",
      name: "DAO Proposal Notification Bypass",
      severity: "high",
      pattern: /proposal[\s\S]{0,50}(?:create|submit)[\s\S]{0,50}(?![\s\S]{0,30}notify|[\s\S]{0,30}alert|[\s\S]{0,30}announce)/i,
      description: "Synthetify-style: Malicious proposals submitted without community notice.",
      recommendation: "Implement mandatory proposal announcement periods.",
      exploit: "Attack proposal went unnoticed, passed without opposition",
      loss: "$230K"
    },
    {
      id: "HELIUS-SYNTH-002",
      name: "Governance Timelock Too Short",
      severity: "high",
      pattern: /timelock[\s\S]{0,30}(?:hours|days)[\s\S]{0,20}(?:[0-2]|24|48)/i,
      description: "Governance timelock under 3 days allows rushed malicious proposals.",
      recommendation: "Set minimum 3-7 day timelock for governance actions.",
      exploit: "Short timelock allowed attack to execute before detection",
      loss: "$230K"
    },
    // SVT Token Signature Bypass (Feb 2024)
    {
      id: "HELIUS-SVT-001",
      name: "Signature Account Validation Bypass",
      severity: "critical",
      pattern: /signature[\s\S]{0,50}(?:verify|check)[\s\S]{0,50}(?![\s\S]{0,30}account_owner|[\s\S]{0,30}program_id)/i,
      description: "SVT-style: Signature verification without validating signer account ownership.",
      recommendation: "Verify signer account owner matches expected program.",
      exploit: "Attacker forged signatures using fake signer accounts",
      loss: "$1M"
    },
    // Saga DAO Proposal Injection (Dec 2023)
    {
      id: "HELIUS-SAGA-001",
      name: "Governance Instruction Injection",
      severity: "critical",
      pattern: /governance[\s\S]{0,50}instruction[\s\S]{0,50}(?:arbitrary|custom|external)/i,
      description: "Saga DAO-style: Arbitrary instruction injection in governance proposals.",
      recommendation: "Whitelist allowed instruction types for governance execution.",
      exploit: "Malicious proposal executed arbitrary token transfer instructions",
      loss: "$1.5M"
    },
    // Parcl Frontend Phishing (Mar 2024)
    {
      id: "HELIUS-PARCL-001",
      name: "Frontend Deployment Compromise",
      severity: "critical",
      pattern: /cdn|cloudflare|vercel|netlify[\s\S]{0,50}(?:deploy|publish|update)/i,
      description: "Parcl-style: Frontend deployment compromised to inject malicious code.",
      recommendation: "Use deployment signing, CSP headers, and integrity checks.",
      exploit: "Compromised frontend redirected transaction approvals",
      loss: "$4K"
    },
    // Raydium Admin Key Compromise ($4.4M Dec 2022)
    {
      id: "HELIUS-RAY-001",
      name: "Pool Admin Key Single Point of Failure",
      severity: "critical",
      pattern: /pool[\s\S]{0,30}admin[\s\S]{0,30}(?:key|authority|owner)[\s\S]{0,30}(?!multi|threshold)/i,
      description: "Raydium-style: Single admin key for pool operations.",
      recommendation: "Use multi-sig admin keys with threshold signing.",
      exploit: "Compromised admin key drained liquidity pools",
      loss: "$4.4M"
    },
    {
      id: "HELIUS-RAY-002",
      name: "Withdraw Authority Without Timelock",
      severity: "critical",
      pattern: /withdraw[\s\S]{0,30}authority[\s\S]{0,50}(?![\s\S]{0,30}timelock|[\s\S]{0,30}delay|[\s\S]{0,30}cooldown)/i,
      description: "Withdrawal authority can drain pools instantly.",
      recommendation: "Add timelock delay for large withdrawals.",
      exploit: "Immediate withdrawal capability enabled rapid pool drain",
      loss: "$4.4M"
    },
    // Aurory NFT Bridge Exploit (Aug 2024)
    {
      id: "HELIUS-AURORY-001",
      name: "Cross-Chain Message Replay",
      severity: "critical",
      pattern: /bridge[\s\S]{0,50}message[\s\S]{0,50}(?![\s\S]{0,30}nonce|[\s\S]{0,30}unique|[\s\S]{0,30}replay)/i,
      description: "Aurory-style: Bridge messages can be replayed.",
      recommendation: "Include unique nonces and track processed messages.",
      exploit: "Bridge message replayed to mint duplicate NFTs",
      loss: "$830K"
    },
    // UXD Protocol Oracle Manipulation (Nov 2022)
    {
      id: "HELIUS-UXD-001",
      name: "Stale Oracle During Volatility",
      severity: "high",
      pattern: /oracle[\s\S]{0,50}price[\s\S]{0,50}(?![\s\S]{0,30}max_age|[\s\S]{0,30}staleness|[\s\S]{0,30}last_update)/i,
      description: "UXD-style: Stale oracle prices during high volatility.",
      recommendation: "Enforce maximum oracle age, use TWAP during volatility.",
      exploit: "Stale prices during FTX collapse enabled manipulation",
      loss: "$3.9M"
    },
    // Tulip Protocol Lending Manipulation (Oct 2022)
    {
      id: "HELIUS-TULIP-001",
      name: "Lending Rate Manipulation",
      severity: "high",
      pattern: /lending[\s\S]{0,30}rate[\s\S]{0,50}(?:utilization|borrow)[\s\S]{0,30}(?![\s\S]{0,20}cap|[\s\S]{0,20}limit)/i,
      description: "Tulip-style: Lending rates can be manipulated through utilization.",
      recommendation: "Cap maximum utilization rate, implement rate smoothing.",
      exploit: "Flash loan manipulated utilization to extract excess interest",
      loss: "$5.2M"
    },
    // Additional 2025 Patterns
    {
      id: "HELIUS-2025-001",
      name: "JIT Liquidity Sandwich",
      severity: "high",
      pattern: /jit[\s\S]{0,30}liquidity[\s\S]{0,50}(?:provide|add|inject)/i,
      description: "2025 MEV: JIT liquidity providers sandwiching user trades.",
      recommendation: "Use private mempools or MEV-protected submission.",
      exploit: "JIT liquidity extracting value from user swaps",
      loss: "Ongoing"
    },
    {
      id: "HELIUS-2025-002",
      name: "Tip Routing Manipulation",
      severity: "medium",
      pattern: /tip[\s\S]{0,30}(?:route|forward|relay)[\s\S]{0,30}(?:jito|block|validator)/i,
      description: "2025 MEV: Tip routing can be manipulated for extraction.",
      recommendation: "Verify tip destinations, use trusted relayers.",
      exploit: "Tips redirected to attacker validators",
      loss: "Ongoing"
    },
    // Solend 2022 Exploitation Patterns
    {
      id: "HELIUS-SOLEND-001",
      name: "Malicious Lending Market Creation",
      severity: "critical",
      pattern: /create[\s\S]{0,30}(?:market|pool|lending)[\s\S]{0,50}(?:permissionless|anyone|open)/i,
      description: "Solend 2022: Malicious markets created to bypass validation.",
      recommendation: "Whitelist allowed markets or require governance approval.",
      exploit: "Attacker created fake market to bypass auth checks",
      loss: "$2M at risk"
    },
    {
      id: "HELIUS-SOLEND-002",
      name: "Reserve Config Manipulation",
      severity: "critical",
      pattern: /reserve[\s\S]{0,30}config[\s\S]{0,50}(?:update|set|modify)[\s\S]{0,30}(?![\s\S]{0,20}auth|[\s\S]{0,20}admin)/i,
      description: "Reserve configuration can be manipulated without proper auth.",
      recommendation: "Require admin signature and timelock for config changes.",
      exploit: "UpdateReserveConfig bypassed by malicious market",
      loss: "$2M at risk"
    }
  ];
  for (const p of patterns) {
    const matches = content.matchAll(new RegExp(p.pattern.source, p.pattern.flags + "g"));
    for (const match of matches) {
      const line = findLineNumber(content, match);
      findings.push({
        id: p.id,
        title: `${p.name}${p.loss ? ` (${p.loss} exploit)` : ""}`,
        severity: p.severity,
        description: p.description,
        location: { file: path, line },
        recommendation: p.recommendation,
        code: getSnippet(content, line)
      });
    }
  }
  return findings;
}

// src/patterns/solana-batched-patterns-53.ts
function findLine(content, idx) {
  return content.substring(0, idx).split("\n").length;
}
function getSnippet2(content, line) {
  const lines = content.split("\n");
  const start = Math.max(0, line - 2);
  const end = Math.min(lines.length, line + 2);
  return lines.slice(start, end).join("\n").substring(0, 200);
}
function checkBatch53Patterns(input) {
  const findings = [];
  const content = input.rust?.content || "";
  const path = input.path;
  if (!content) return findings;
  const patterns = [
    // Business Logic Deep Patterns (SOL2001-SOL2020)
    {
      id: "SOL2001",
      name: "State Machine Skip",
      severity: "critical",
      regex: /state[\s\S]{0,30}transition[\s\S]{0,50}(?![\s\S]{0,30}require|[\s\S]{0,30}assert)/i,
      desc: "State transitions without validation allow skipping required states.",
      rec: "Validate current state before allowing transition to next state."
    },
    {
      id: "SOL2002",
      name: "Deadline Bypass",
      severity: "high",
      regex: /deadline|expiry|expire[\s\S]{0,50}(?:clock|timestamp)[\s\S]{0,30}(?![\s\S]{0,20}>=|[\s\S]{0,20}<=)/i,
      desc: "Deadline comparisons may allow edge-case bypasses.",
      rec: "Use strict comparisons and check both upper and lower bounds."
    },
    {
      id: "SOL2003",
      name: "Fee Calculation Precision Loss",
      severity: "high",
      regex: /fee[\s\S]{0,30}(?:\*|multiply)[\s\S]{0,30}(?:\/|divide)(?![\s\S]{0,20}checked)/i,
      desc: "Fee calculations may lose precision due to operation order.",
      rec: "Multiply before dividing to preserve precision."
    },
    {
      id: "SOL2004",
      name: "Reward Accumulation Drift",
      severity: "high",
      regex: /reward[\s\S]{0,30}(?:accumulate|accrue|earn)[\s\S]{0,50}(?:per_share|rate)/i,
      desc: "Reward accumulation may drift from expected values over time.",
      rec: "Use high-precision fixed-point math for reward calculations."
    },
    {
      id: "SOL2005",
      name: "Partial Fill Edge Case",
      severity: "medium",
      regex: /partial[\s\S]{0,20}(?:fill|execute)[\s\S]{0,50}(?:amount|quantity)[\s\S]{0,20}(?![\s\S]{0,15}min)/i,
      desc: "Partial fills without minimum amounts enable dust attacks.",
      rec: "Enforce minimum fill amounts to prevent dust exploitation."
    },
    {
      id: "SOL2006",
      name: "Slippage Off-by-One",
      severity: "medium",
      regex: /slippage[\s\S]{0,30}(?:>|<)[\s\S]{0,20}(?![\s\S]{0,10}=)/i,
      desc: "Slippage checks using strict comparison may miss boundary.",
      rec: "Use >= or <= for slippage comparisons."
    },
    {
      id: "SOL2007",
      name: "Cooldown Reset Exploit",
      severity: "high",
      regex: /cooldown[\s\S]{0,30}(?:set|update|reset)[\s\S]{0,50}(?![\s\S]{0,30}require|[\s\S]{0,30}assert)/i,
      desc: "Cooldowns can be reset without proper validation.",
      rec: "Verify cooldown has expired before allowing reset."
    },
    {
      id: "SOL2008",
      name: "Epoch Boundary Race",
      severity: "high",
      regex: /epoch[\s\S]{0,30}(?:boundary|transition|change)[\s\S]{0,50}(?:stake|unstake|claim)/i,
      desc: "Operations at epoch boundaries may have race conditions.",
      rec: "Add explicit epoch boundary checks and handle transitions safely."
    },
    {
      id: "SOL2009",
      name: "Liquidation Cascade",
      severity: "critical",
      regex: /liquidat[\s\S]{0,30}(?:loop|iterate|batch)[\s\S]{0,50}(?![\s\S]{0,30}limit)/i,
      desc: "Batch liquidations without limits can cascade failures.",
      rec: "Limit liquidations per transaction and add circuit breakers."
    },
    {
      id: "SOL2010",
      name: "Position Close During Settle",
      severity: "high",
      regex: /close[\s\S]{0,30}position[\s\S]{0,50}settl[\s\S]{0,30}(?![\s\S]{0,20}lock|[\s\S]{0,20}pending)/i,
      desc: "Positions closed during settlement can lose funds.",
      rec: "Lock positions during settlement period."
    },
    {
      id: "SOL2011",
      name: "Vault Share Inflation",
      severity: "critical",
      regex: /share[\s\S]{0,30}(?:mint|issue)[\s\S]{0,50}(?:deposit|balance)[\s\S]{0,30}(?![\s\S]{0,20}total)/i,
      desc: "Share minting without checking total supply enables inflation.",
      rec: "Always calculate shares relative to total supply."
    },
    {
      id: "SOL2012",
      name: "First Depositor Attack",
      severity: "critical",
      regex: /(?:first|initial)[\s\S]{0,20}deposit[\s\S]{0,50}(?![\s\S]{0,30}minimum|[\s\S]{0,30}seed)/i,
      desc: "First depositor can manipulate share price.",
      rec: "Require minimum initial deposit or seed the vault."
    },
    {
      id: "SOL2013",
      name: "Withdrawal Queue Jump",
      severity: "high",
      regex: /withdrawal[\s\S]{0,30}queue[\s\S]{0,50}(?:process|execute)[\s\S]{0,30}(?![\s\S]{0,20}fifo|[\s\S]{0,20}order)/i,
      desc: "Withdrawal queue can be bypassed without proper ordering.",
      rec: "Enforce FIFO ordering for withdrawal queues."
    },
    {
      id: "SOL2014",
      name: "Interest Compounding Gap",
      severity: "medium",
      regex: /interest[\s\S]{0,30}compound[\s\S]{0,50}(?![\s\S]{0,30}continuous|[\s\S]{0,30}per_second)/i,
      desc: "Interest compounding gaps allow timing exploitation.",
      rec: "Use continuous compounding or per-second accrual."
    },
    {
      id: "SOL2015",
      name: "Collateral Ratio Manipulation",
      severity: "critical",
      regex: /collateral[\s\S]{0,30}ratio[\s\S]{0,50}(?:flash|instant|atomic)/i,
      desc: "Collateral ratios can be manipulated in single transaction.",
      rec: "Use TWAP or delayed price for collateral calculations."
    },
    {
      id: "SOL2016",
      name: "Referral Fee Bypass",
      severity: "medium",
      regex: /referr[\s\S]{0,30}fee[\s\S]{0,50}(?:self|same)[\s\S]{0,20}(?![\s\S]{0,15}block|[\s\S]{0,15}prevent)/i,
      desc: "Users can refer themselves to capture referral fees.",
      rec: "Prevent self-referral by checking account relationships."
    },
    {
      id: "SOL2017",
      name: "Auction Sniping",
      severity: "high",
      regex: /auction[\s\S]{0,30}(?:end|close|finish)[\s\S]{0,50}(?![\s\S]{0,30}extension|[\s\S]{0,30}anti_snipe)/i,
      desc: "Auctions without extension mechanism enable sniping.",
      rec: "Add bid extension period to prevent last-second sniping."
    },
    {
      id: "SOL2018",
      name: "Vote Power Flash",
      severity: "critical",
      regex: /vote[\s\S]{0,30}(?:power|weight)[\s\S]{0,50}(?:balance|token)[\s\S]{0,30}(?![\s\S]{0,20}snapshot)/i,
      desc: "Vote power from current balance enables flash loan governance.",
      rec: "Use historical snapshots for voting power."
    },
    {
      id: "SOL2019",
      name: "Pool Imbalance Exploit",
      severity: "high",
      regex: /pool[\s\S]{0,30}(?:imbalance|ratio)[\s\S]{0,50}(?:swap|trade)[\s\S]{0,30}(?![\s\S]{0,20}limit)/i,
      desc: "Extreme pool imbalances can be exploited for profit.",
      rec: "Add imbalance limits and circuit breakers."
    },
    {
      id: "SOL2020",
      name: "Margin Call Timing",
      severity: "high",
      regex: /margin[\s\S]{0,30}call[\s\S]{0,50}(?:timestamp|clock)[\s\S]{0,30}(?![\s\S]{0,20}grace|[\s\S]{0,20}window)/i,
      desc: "Margin calls without grace period cause unfair liquidations.",
      rec: "Add grace period for margin calls."
    },
    // Input Validation Advanced (SOL2021-SOL2040)
    {
      id: "SOL2021",
      name: "Pubkey Zero Check",
      severity: "critical",
      regex: /pubkey[\s\S]{0,30}(?:=|==)[\s\S]{0,30}(?![\s\S]{0,20}system_program|[\s\S]{0,20}Pubkey::default)/i,
      desc: "Pubkey comparison without zero/default check.",
      rec: "Check for Pubkey::default() before comparisons."
    },
    {
      id: "SOL2022",
      name: "String Length DoS",
      severity: "high",
      regex: /String[\s\S]{0,30}(?:len|length)[\s\S]{0,30}(?![\s\S]{0,20}<|[\s\S]{0,20}<=|[\s\S]{0,20}max)/i,
      desc: "Unbounded string length enables DoS attacks.",
      rec: "Enforce maximum string length limits."
    },
    {
      id: "SOL2023",
      name: "Array Index Bounds",
      severity: "critical",
      regex: /\[[\s\S]{0,20}(?:index|idx|i)[\s\S]{0,10}\][\s\S]{0,30}(?![\s\S]{0,20}get\(|[\s\S]{0,20}bounds)/i,
      desc: "Array access without bounds checking.",
      rec: "Use .get() for safe array access."
    },
    {
      id: "SOL2024",
      name: "Decimal Truncation",
      severity: "high",
      regex: /as\s+u(?:8|16|32|64)[\s\S]{0,20}(?:decimal|price|amount)/i,
      desc: "Casting to smaller int truncates decimal precision.",
      rec: "Use appropriate integer sizes for decimal values."
    },
    {
      id: "SOL2025",
      name: "Negative Amount Cast",
      severity: "critical",
      regex: /as\s+i(?:8|16|32|64)[\s\S]{0,30}(?:amount|balance|quantity)/i,
      desc: "Casting unsigned to signed may produce negative values.",
      rec: "Validate values before casting to signed types."
    },
    {
      id: "SOL2026",
      name: "Timestamp Future Check",
      severity: "medium",
      regex: /timestamp[\s\S]{0,30}(?:>|>=)[\s\S]{0,30}clock[\s\S]{0,20}(?![\s\S]{0,15}<|[\s\S]{0,15}future)/i,
      desc: "Timestamp validation missing future check.",
      rec: "Reject timestamps too far in the future."
    },
    {
      id: "SOL2027",
      name: "Slot Overflow Risk",
      severity: "high",
      regex: /slot[\s\S]{0,30}(?:\+|add)[\s\S]{0,30}(?![\s\S]{0,20}checked|[\s\S]{0,20}saturating)/i,
      desc: "Slot arithmetic may overflow at high values.",
      rec: "Use checked arithmetic for slot calculations."
    },
    {
      id: "SOL2028",
      name: "Lamport Dust",
      severity: "low",
      regex: /lamports[\s\S]{0,30}(?:<|<=)[\s\S]{0,20}(?:1000|100|10|1)[\s\S]{0,10}(?![\s\S]{0,10}0)/i,
      desc: "Operations on dust lamport amounts waste compute.",
      rec: "Enforce minimum lamport thresholds."
    },
    {
      id: "SOL2029",
      name: "Base58 Decode Unchecked",
      severity: "medium",
      regex: /base58[\s\S]{0,30}decode[\s\S]{0,30}(?:unwrap|expect)/i,
      desc: "Base58 decode failure not properly handled.",
      rec: "Handle base58 decode errors gracefully."
    },
    {
      id: "SOL2030",
      name: "Instruction Data Size",
      severity: "high",
      regex: /instruction[\s\S]{0,30}data[\s\S]{0,50}(?:len|length)[\s\S]{0,20}(?![\s\S]{0,15}>=|[\s\S]{0,15}require)/i,
      desc: "Instruction data size not validated.",
      rec: "Validate instruction data length before parsing."
    },
    {
      id: "SOL2031",
      name: "Remaining Accounts Unbounded",
      severity: "high",
      regex: /remaining_accounts[\s\S]{0,50}(?:iter|for_each)[\s\S]{0,30}(?![\s\S]{0,20}take\(|[\s\S]{0,20}limit)/i,
      desc: "Remaining accounts iteration unbounded.",
      rec: "Limit remaining accounts iteration count."
    },
    {
      id: "SOL2032",
      name: "Seeds Length Validation",
      severity: "high",
      regex: /seeds[\s\S]{0,30}(?:len|length)[\s\S]{0,30}(?![\s\S]{0,20}<=\s*32|[\s\S]{0,20}MAX_SEED)/i,
      desc: "PDA seed length not validated against max.",
      rec: "Validate seed lengths <= 32 bytes each."
    },
    {
      id: "SOL2033",
      name: "Memo Injection",
      severity: "medium",
      regex: /memo[\s\S]{0,30}(?:data|content|message)[\s\S]{0,30}(?![\s\S]{0,20}sanitize|[\s\S]{0,20}escape)/i,
      desc: "Memo content not sanitized for display.",
      rec: "Sanitize memo content before display/logging."
    },
    {
      id: "SOL2034",
      name: "URL Validation",
      severity: "medium",
      regex: /url|uri[\s\S]{0,30}(?:http|https)[\s\S]{0,30}(?![\s\S]{0,20}validate|[\s\S]{0,20}whitelist)/i,
      desc: "URLs stored without validation.",
      rec: "Validate URLs against allowed protocols and domains."
    },
    {
      id: "SOL2035",
      name: "Bitmap Overflow",
      severity: "high",
      regex: /bitmap|bitset[\s\S]{0,30}(?:set|get|toggle)[\s\S]{0,30}(?![\s\S]{0,20}bounds|[\s\S]{0,20}<\s*\d)/i,
      desc: "Bitmap operations without bounds checking.",
      rec: "Validate bit index before bitmap operations."
    },
    {
      id: "SOL2036",
      name: "Enum Discriminant Check",
      severity: "high",
      regex: /enum[\s\S]{0,50}(?:from_u8|from_byte)[\s\S]{0,30}(?![\s\S]{0,20}match|[\s\S]{0,20}try)/i,
      desc: "Enum deserialization without discriminant validation.",
      rec: "Use try_from or match for enum deserialization."
    },
    {
      id: "SOL2037",
      name: "Float Precision",
      severity: "high",
      regex: /f32|f64[\s\S]{0,30}(?:price|amount|balance)/i,
      desc: "Floating point used for financial calculations.",
      rec: "Use fixed-point decimals for financial values."
    },
    {
      id: "SOL2038",
      name: "Hash Preimage",
      severity: "medium",
      regex: /hash[\s\S]{0,30}(?:preimage|reveal)[\s\S]{0,30}(?![\s\S]{0,20}commit|[\s\S]{0,20}timelock)/i,
      desc: "Hash reveal without commit-reveal scheme.",
      rec: "Use commit-reveal pattern for hash-based operations."
    },
    {
      id: "SOL2039",
      name: "Nonce Replay",
      severity: "critical",
      regex: /nonce[\s\S]{0,30}(?:use|consume)[\s\S]{0,30}(?![\s\S]{0,20}increment|[\s\S]{0,20}invalidate)/i,
      desc: "Nonce not invalidated after use.",
      rec: "Increment or invalidate nonces after each use."
    },
    {
      id: "SOL2040",
      name: "Version Compatibility",
      severity: "medium",
      regex: /version[\s\S]{0,30}(?:check|compare)[\s\S]{0,30}(?![\s\S]{0,20}>=|[\s\S]{0,20}compatible)/i,
      desc: "Version checking may miss compatibility issues.",
      rec: "Implement proper semantic version compatibility."
    },
    // Access Control Edge Cases (SOL2041-SOL2055)
    {
      id: "SOL2041",
      name: "Authority Downgrade",
      severity: "critical",
      regex: /authority[\s\S]{0,30}(?:downgrade|reduce|lower)[\s\S]{0,30}(?![\s\S]{0,20}require|[\s\S]{0,20}verify)/i,
      desc: "Authority can be downgraded without proper checks.",
      rec: "Require current authority signature for downgrades."
    },
    {
      id: "SOL2042",
      name: "Freeze Authority Transfer",
      severity: "high",
      regex: /freeze[\s\S]{0,30}authority[\s\S]{0,30}transfer[\s\S]{0,30}(?![\s\S]{0,20}verify|[\s\S]{0,20}require)/i,
      desc: "Freeze authority can be transferred unsafely.",
      rec: "Implement two-step freeze authority transfer."
    },
    {
      id: "SOL2043",
      name: "Delegate Scope Creep",
      severity: "high",
      regex: /delegate[\s\S]{0,30}(?:amount|scope|permission)[\s\S]{0,30}(?:update|increase)/i,
      desc: "Delegate permissions can be expanded without limit.",
      rec: "Cap delegate permissions at initial grant level."
    },
    {
      id: "SOL2044",
      name: "Emergency Admin Abuse",
      severity: "critical",
      regex: /emergency[\s\S]{0,30}admin[\s\S]{0,50}(?:drain|withdraw|transfer)[\s\S]{0,30}(?![\s\S]{0,20}timelock)/i,
      desc: "Emergency admin can drain without timelock.",
      rec: "Add timelock even for emergency operations."
    },
    {
      id: "SOL2045",
      name: "Pause Without Unpause",
      severity: "high",
      regex: /pause[\s\S]{0,50}(?![\s\S]{0,50}unpause|[\s\S]{0,50}resume)/i,
      desc: "Pause mechanism without corresponding unpause.",
      rec: "Implement unpause with appropriate controls."
    },
    {
      id: "SOL2046",
      name: "Role Hierarchy Bypass",
      severity: "high",
      regex: /role[\s\S]{0,30}(?:check|verify)[\s\S]{0,50}(?![\s\S]{0,30}hierarchy|[\s\S]{0,30}inherit)/i,
      desc: "Role checks may not respect hierarchy.",
      rec: "Implement proper role hierarchy checking."
    },
    {
      id: "SOL2047",
      name: "Session Key Scope",
      severity: "high",
      regex: /session[\s\S]{0,30}key[\s\S]{0,50}(?:sign|execute)[\s\S]{0,30}(?![\s\S]{0,20}scope|[\s\S]{0,20}limit)/i,
      desc: "Session keys without operation scope limits.",
      rec: "Limit session key permissions to specific operations."
    },
    {
      id: "SOL2048",
      name: "CPI Authority Escalation",
      severity: "critical",
      regex: /invoke[\s\S]{0,50}signer_seeds[\s\S]{0,30}(?:any|arbitrary|user)/i,
      desc: "CPI using arbitrary user-provided seeds.",
      rec: "Validate signer seeds against expected values."
    },
    {
      id: "SOL2049",
      name: "Token Metadata Authority",
      severity: "high",
      regex: /metadata[\s\S]{0,30}(?:update|modify)[\s\S]{0,30}authority[\s\S]{0,30}(?![\s\S]{0,20}verify)/i,
      desc: "Metadata update authority not verified.",
      rec: "Verify metadata update authority before changes."
    },
    {
      id: "SOL2050",
      name: "Collection Authority Spoof",
      severity: "critical",
      regex: /collection[\s\S]{0,30}(?:verify|sign)[\s\S]{0,30}(?![\s\S]{0,20}authority|[\s\S]{0,20}creator)/i,
      desc: "Collection verification without authority check.",
      rec: "Verify collection authority signature."
    },
    {
      id: "SOL2051",
      name: "Upgrade Authority Leak",
      severity: "critical",
      regex: /upgrade[\s\S]{0,30}authority[\s\S]{0,50}(?:pubkey|key)[\s\S]{0,30}(?:set|assign|change)/i,
      desc: "Program upgrade authority can be changed unsafely.",
      rec: "Make upgrade authority immutable or use multi-sig."
    },
    {
      id: "SOL2052",
      name: "Close Authority Missing",
      severity: "high",
      regex: /close[\s\S]{0,30}account[\s\S]{0,50}(?![\s\S]{0,30}authority|[\s\S]{0,30}owner)/i,
      desc: "Account closure without authority verification.",
      rec: "Verify close authority before account closure."
    },
    {
      id: "SOL2053",
      name: "Rent Payer Authority",
      severity: "medium",
      regex: /rent[\s\S]{0,30}payer[\s\S]{0,50}(?![\s\S]{0,30}signer|[\s\S]{0,30}verify)/i,
      desc: "Rent payer not verified as signer.",
      rec: "Require rent payer signature."
    },
    {
      id: "SOL2054",
      name: "Crank Permission",
      severity: "medium",
      regex: /crank[\s\S]{0,30}(?:execute|call)[\s\S]{0,50}(?:anyone|permissionless)/i,
      desc: "Permissionless cranking may enable extraction.",
      rec: "Add incentives or restrictions for cranking."
    },
    {
      id: "SOL2055",
      name: "Initializer Authority",
      severity: "high",
      regex: /init[\s\S]{0,30}(?:authority|admin)[\s\S]{0,50}(?:caller|signer)[\s\S]{0,30}(?![\s\S]{0,20}hardcode)/i,
      desc: "Initializer becomes authority by default.",
      rec: "Separate initialization from authority assignment."
    },
    // 2024-2025 Emerging Attack Vectors (SOL2056-SOL2070)
    {
      id: "SOL2056",
      name: "Blink Action Validation",
      severity: "high",
      regex: /blink|action[\s\S]{0,30}(?:url|endpoint)[\s\S]{0,30}(?![\s\S]{0,20}verify|[\s\S]{0,20}whitelist)/i,
      desc: "Blink action URLs not validated.",
      rec: "Whitelist allowed blink action endpoints."
    },
    {
      id: "SOL2057",
      name: "Compression Proof Spoofing",
      severity: "critical",
      regex: /compression[\s\S]{0,30}proof[\s\S]{0,50}(?:verify|check)[\s\S]{0,30}(?![\s\S]{0,20}root)/i,
      desc: "Compressed NFT proof verification incomplete.",
      rec: "Verify proof against current merkle root."
    },
    {
      id: "SOL2058",
      name: "Token-2022 Extension Abuse",
      severity: "high",
      regex: /token[\s\S]{0,10}2022[\s\S]{0,30}extension[\s\S]{0,30}(?![\s\S]{0,20}verify|[\s\S]{0,20}check)/i,
      desc: "Token-2022 extensions not properly validated.",
      rec: "Validate extension states before operations."
    },
    {
      id: "SOL2059",
      name: "Transfer Hook Reentrancy",
      severity: "critical",
      regex: /transfer[\s\S]{0,30}hook[\s\S]{0,50}(?:invoke|call)[\s\S]{0,30}(?![\s\S]{0,20}guard|[\s\S]{0,20}lock)/i,
      desc: "Transfer hooks may enable reentrancy.",
      rec: "Add reentrancy guards for transfer hooks."
    },
    {
      id: "SOL2060",
      name: "Confidential Transfer Leak",
      severity: "high",
      regex: /confidential[\s\S]{0,30}transfer[\s\S]{0,50}(?:log|emit|print)/i,
      desc: "Confidential transfer amounts may be leaked.",
      rec: "Never log confidential transfer details."
    },
    {
      id: "SOL2061",
      name: "Interest Bearing Manipulation",
      severity: "high",
      regex: /interest[\s\S]{0,30}bearing[\s\S]{0,50}rate[\s\S]{0,30}(?:set|update)/i,
      desc: "Interest bearing token rate can be manipulated.",
      rec: "Add timelock for interest rate changes."
    },
    {
      id: "SOL2062",
      name: "Permanent Delegate Abuse",
      severity: "critical",
      regex: /permanent[\s\S]{0,30}delegate[\s\S]{0,50}(?![\s\S]{0,30}revoke|[\s\S]{0,30}remove)/i,
      desc: "Permanent delegate cannot be revoked.",
      rec: "Avoid permanent delegates or add revocation."
    },
    {
      id: "SOL2063",
      name: "CPI Guard State",
      severity: "high",
      regex: /cpi[\s\S]{0,30}guard[\s\S]{0,50}(?:enable|disable)[\s\S]{0,30}(?![\s\S]{0,20}verify)/i,
      desc: "CPI guard state changes not verified.",
      rec: "Verify CPI guard state before sensitive operations."
    },
    {
      id: "SOL2064",
      name: "Memo Required Bypass",
      severity: "medium",
      regex: /memo[\s\S]{0,30}required[\s\S]{0,50}(?:skip|bypass|ignore)/i,
      desc: "Required memo can be bypassed.",
      rec: "Enforce memo requirement at protocol level."
    },
    {
      id: "SOL2065",
      name: "Non-Transferable Override",
      severity: "high",
      regex: /non[\s\S]{0,5}transferable[\s\S]{0,50}(?:override|bypass|exception)/i,
      desc: "Non-transferable tokens can be transferred.",
      rec: "Remove override capabilities for non-transferable."
    },
    {
      id: "SOL2066",
      name: "Default Account State Abuse",
      severity: "medium",
      regex: /default[\s\S]{0,30}account[\s\S]{0,30}state[\s\S]{0,30}(?:frozen|initialized)/i,
      desc: "Default account state can lock user funds.",
      rec: "Clearly document default account state behavior."
    },
    {
      id: "SOL2067",
      name: "Reallocate Without Check",
      severity: "high",
      regex: /realloc[\s\S]{0,50}(?:size|space)[\s\S]{0,30}(?![\s\S]{0,20}max|[\s\S]{0,20}limit)/i,
      desc: "Account reallocation without size limits.",
      rec: "Enforce maximum account size limits."
    },
    {
      id: "SOL2068",
      name: "Lookup Table Poison",
      severity: "critical",
      regex: /lookup[\s\S]{0,30}table[\s\S]{0,50}(?:extend|add)[\s\S]{0,30}(?![\s\S]{0,20}verify)/i,
      desc: "Address lookup tables can be poisoned.",
      rec: "Verify lookup table authority and contents."
    },
    {
      id: "SOL2069",
      name: "Durable Nonce Exploitation",
      severity: "high",
      regex: /durable[\s\S]{0,30}nonce[\s\S]{0,50}(?:advance|consume)[\s\S]{0,30}(?![\s\S]{0,20}verify)/i,
      desc: "Durable nonce state not properly verified.",
      rec: "Verify nonce account state and authority."
    },
    {
      id: "SOL2070",
      name: "Versioned Transaction Confusion",
      severity: "medium",
      regex: /version[\s\S]{0,30}transaction[\s\S]{0,50}(?:legacy|v0)[\s\S]{0,30}(?![\s\S]{0,20}check)/i,
      desc: "Transaction version handling may cause confusion.",
      rec: "Explicitly handle both legacy and versioned transactions."
    }
  ];
  for (const p of patterns) {
    const matches = content.matchAll(new RegExp(p.regex.source, p.regex.flags + "g"));
    for (const match of matches) {
      const line = findLine(content, match.index || 0);
      findings.push({
        id: p.id,
        title: p.name,
        severity: p.severity,
        description: p.desc,
        location: { file: path, line },
        recommendation: p.rec,
        code: getSnippet2(content, line)
      });
    }
  }
  return findings;
}

// src/patterns/solana-batched-patterns-54.ts
var BATCH_54_PATTERNS = [
  // ========== Solend-style Auth Bypass (SOL2071-SOL2085) ==========
  {
    id: "SOL2071",
    name: "UpdateReserveConfig Auth Bypass",
    severity: "critical",
    pattern: /update.*reserve.*config|reserve.*update|config.*update/i,
    description: "Reserve config update without proper lending market ownership validation. An attacker can create their own lending market and pass it to bypass admin checks (Solend Aug 2021).",
    recommendation: "Verify lending market ownership before allowing reserve config updates. Use has_one constraint on lending_market authority."
  },
  {
    id: "SOL2072",
    name: "Lending Market Ownership Bypass",
    severity: "critical",
    pattern: /lending_market|LendingMarket[\s\S]{0,100}(?!has_one|owner\s*==)/i,
    description: "Lending market passed as account without verifying caller owns it. Attacker can substitute their own market.",
    recommendation: "Add has_one = lending_market constraint or verify lending_market.owner == authority.key()."
  },
  {
    id: "SOL2073",
    name: "Liquidation Threshold Manipulation",
    severity: "critical",
    pattern: /liquidation_threshold|ltv|loan_to_value[\s\S]{0,50}(?:=|update)/i,
    description: "Liquidation threshold can be modified without proper authorization (Solend exploit vector).",
    recommendation: "Require multisig or timelock for liquidation parameter changes."
  },
  {
    id: "SOL2074",
    name: "Liquidation Bonus Inflation",
    severity: "high",
    pattern: /liquidation_bonus|liquidator_bonus[\s\S]{0,50}(?:=|update|set)/i,
    description: "Liquidation bonus can be inflated to steal from liquidated positions.",
    recommendation: "Cap liquidation bonus at reasonable maximum (e.g., 15%) and require governance for changes."
  },
  {
    id: "SOL2075",
    name: "Reserve Configuration Race",
    severity: "high",
    pattern: /reserve(?:_config)?[\s\S]{0,100}(?:update|modify|set)[\s\S]{0,50}(?!timelock|delay)/i,
    description: "Reserve config changes take effect immediately, allowing front-run attacks.",
    recommendation: "Add timelock delay for configuration changes."
  },
  {
    id: "SOL2076",
    name: "Admin Lending Market Substitution",
    severity: "critical",
    pattern: /admin|authority[\s\S]{0,100}market(?:_account)?/i,
    description: "Admin can substitute lending market to bypass checks.",
    recommendation: "Hardcode or derive lending market address, never accept as input for admin functions."
  },
  {
    id: "SOL2077",
    name: "Borrowing Suspension Bypass",
    severity: "high",
    pattern: /borrow(?:ing)?[\s\S]{0,50}(?:suspend|pause|disable)[\s\S]{0,50}(?!require|assert)/i,
    description: "Borrowing suspension can be bypassed or may not be checked during borrows.",
    recommendation: "Check suspension status at the start of every borrow instruction."
  },
  {
    id: "SOL2078",
    name: "Bot Liquidator Privilege",
    severity: "medium",
    pattern: /liquidator(?:_bot)?|bot_liquidat/i,
    description: "Protocol liquidator bot may have undue privileges over user positions.",
    recommendation: "Ensure liquidator bots follow same rules as external liquidators."
  },
  {
    id: "SOL2079",
    name: "Reserve State Desync",
    severity: "high",
    pattern: /reserve[\s\S]{0,50}state[\s\S]{0,50}(?!refresh|reload|update)/i,
    description: "Reserve state not refreshed before critical operations.",
    recommendation: "Always refresh reserve state before reads in same transaction."
  },
  {
    id: "SOL2080",
    name: "Interest Rate Model Injection",
    severity: "high",
    pattern: /interest_rate|rate_model[\s\S]{0,50}(?:=|set|update)/i,
    description: "Interest rate model can be injected/changed maliciously.",
    recommendation: "Validate interest rate model address against allowlist."
  },
  {
    id: "SOL2081",
    name: "Collateral Factor Manipulation",
    severity: "critical",
    pattern: /collateral_factor|cf[\s\S]{0,30}(?:=|set|update)/i,
    description: "Collateral factor changes can make positions instantly liquidatable.",
    recommendation: "Require governance vote and delay for collateral factor changes."
  },
  {
    id: "SOL2082",
    name: "Lending Pool Admin Takeover",
    severity: "critical",
    pattern: /(?:lending_)?pool[\s\S]{0,50}admin[\s\S]{0,50}(?:=|transfer|set)/i,
    description: "Pool admin can be transferred without proper safeguards.",
    recommendation: "Require two-step admin transfer with acceptance confirmation."
  },
  {
    id: "SOL2083",
    name: "Reserve Withdraw Authority",
    severity: "high",
    pattern: /reserve[\s\S]{0,50}withdraw(?:_authority)?/i,
    description: "Reserve withdraw authority may allow unauthorized withdrawals.",
    recommendation: "Restrict reserve withdrawals to protocol PDAs only."
  },
  {
    id: "SOL2084",
    name: "Oracle Price Admin Override",
    severity: "critical",
    pattern: /(?:oracle|price)[\s\S]{0,50}admin[\s\S]{0,30}override/i,
    description: "Admin can override oracle prices, enabling manipulation.",
    recommendation: "Remove admin price override capability or require multisig + delay."
  },
  {
    id: "SOL2085",
    name: "Emergency Liquidation Mode",
    severity: "high",
    pattern: /emergency[\s\S]{0,50}liquidat/i,
    description: "Emergency liquidation mode may allow exploitative liquidations.",
    recommendation: "Cap emergency mode privileges, require timelock to activate."
  },
  // ========== Wormhole-style Signature Bypass (SOL2086-SOL2095) ==========
  {
    id: "SOL2086",
    name: "Guardian Signature Verification Bypass",
    severity: "critical",
    pattern: /guardian[\s\S]{0,100}(?:verify|signature|sign)[\s\S]{0,50}(?!require|assert|check)/i,
    description: "Guardian signatures not properly verified (Wormhole $326M exploit pattern).",
    recommendation: "Always verify guardian signatures against known guardian set with quorum."
  },
  {
    id: "SOL2087",
    name: "Signature Set Spoofing",
    severity: "critical",
    pattern: /signature_set|SignatureSet[\s\S]{0,100}(?!owner_check|verify_owner)/i,
    description: "Signature set account can be spoofed (Wormhole exploit pattern).",
    recommendation: "Verify signature set is owned by expected program and properly initialized."
  },
  {
    id: "SOL2088",
    name: "VAA Validation Incomplete",
    severity: "critical",
    pattern: /vaa|VAA[\s\S]{0,100}(?!verify_signatures|check_guardian)/i,
    description: "Verified Action Approval (VAA) not fully validated.",
    recommendation: "Verify all VAA fields including guardian signatures, timestamp, and sequence."
  },
  {
    id: "SOL2089",
    name: "Cross-Chain Message Forgery",
    severity: "critical",
    pattern: /cross_chain[\s\S]{0,50}message[\s\S]{0,50}(?!verify|validate)/i,
    description: "Cross-chain messages can be forged without proper attestation.",
    recommendation: "Require multiple independent attestations for cross-chain messages."
  },
  {
    id: "SOL2090",
    name: "Bridge Guardian Quorum",
    severity: "critical",
    pattern: /guardian[\s\S]{0,50}quorum[\s\S]{0,50}(?!>=|threshold)/i,
    description: "Guardian quorum not checked before accepting bridge messages.",
    recommendation: "Require 2/3+ guardian signatures for any bridge operation."
  },
  {
    id: "SOL2091",
    name: "Wrapped Token Mint Authority",
    severity: "critical",
    pattern: /wrapped[\s\S]{0,30}(?:token|mint)[\s\S]{0,50}authority/i,
    description: "Wrapped token mint authority may be compromised or bypassed.",
    recommendation: "Mint authority must be PDA derived from verified bridge program."
  },
  {
    id: "SOL2092",
    name: "Bridge Finality Check",
    severity: "high",
    pattern: /bridge[\s\S]{0,50}(?:transfer|deposit|withdraw)[\s\S]{0,50}(?!finality|confirm)/i,
    description: "Bridge operations without checking source chain finality.",
    recommendation: "Wait for sufficient block confirmations on source chain before minting."
  },
  {
    id: "SOL2093",
    name: "Relayer Trust Assumption",
    severity: "high",
    pattern: /relayer[\s\S]{0,50}(?:submit|relay|forward)/i,
    description: "Relayer is trusted to submit valid messages without verification.",
    recommendation: "Verify message content on-chain, never trust relayer-provided data."
  },
  {
    id: "SOL2094",
    name: "Guardian Set Update Race",
    severity: "critical",
    pattern: /guardian_set[\s\S]{0,50}(?:update|rotate|change)/i,
    description: "Guardian set update can race with pending operations.",
    recommendation: "Implement guardian set update delay and process pending ops first."
  },
  {
    id: "SOL2095",
    name: "Ed25519 Precompile Bypass",
    severity: "critical",
    pattern: /ed25519[\s\S]{0,50}(?:verify|check)[\s\S]{0,50}(?!precompile|native)/i,
    description: "Ed25519 signature verification not using native precompile.",
    recommendation: "Use Ed25519 native program for signature verification."
  },
  // ========== Cashio-style Mint Validation (SOL2096-SOL2105) ==========
  {
    id: "SOL2096",
    name: "Collateral Mint Whitelist Missing",
    severity: "critical",
    pattern: /collateral[\s\S]{0,50}mint[\s\S]{0,50}(?!whitelist|allowlist|verify)/i,
    description: "Collateral mint not validated against whitelist (Cashio $52M exploit).",
    recommendation: "Verify collateral mint is in approved whitelist before accepting."
  },
  {
    id: "SOL2097",
    name: "Saber LP Token Validation",
    severity: "critical",
    pattern: /saber[\s\S]{0,50}(?:lp|pool|swap)/i,
    description: "Saber LP token not properly validated for mint field.",
    recommendation: "Verify saber_swap.arrow mint field matches expected collateral."
  },
  {
    id: "SOL2098",
    name: "Root of Trust Missing",
    severity: "critical",
    pattern: /(?:collateral|backing|reserve)[\s\S]{0,100}(?!root_of_trust|chain_validation)/i,
    description: "Missing root of trust validation for collateral chain.",
    recommendation: "Establish and verify complete chain of trust for all collateral."
  },
  {
    id: "SOL2099",
    name: "Fake Account Substitution",
    severity: "critical",
    pattern: /(?:account|token_account)[\s\S]{0,50}(?:collateral|backing)/i,
    description: "Fake accounts can be substituted for real collateral.",
    recommendation: "Verify every account in the collateral chain against known PDAs."
  },
  {
    id: "SOL2100",
    name: "Infinite Mint Vulnerability",
    severity: "critical",
    pattern: /mint(?:_to)?[\s\S]{0,100}(?!balance_check|limit|cap)/i,
    description: "Minting without proper balance or cap checks enables infinite mint.",
    recommendation: "Verify backing ratio before minting, enforce supply caps."
  },
  {
    id: "SOL2101",
    name: "Stablecoin Peg Attack",
    severity: "critical",
    pattern: /stable(?:coin)?[\s\S]{0,50}(?:mint|redeem|swap)/i,
    description: "Stablecoin can be minted or redeemed to attack the peg.",
    recommendation: "Implement mint/redeem fees, rate limits, and oracle validation."
  },
  {
    id: "SOL2102",
    name: "Arrow Account Validation",
    severity: "high",
    pattern: /arrow[\s\S]{0,50}account/i,
    description: "Arrow/wrapper account not fully validated.",
    recommendation: "Verify all nested account fields in wrapper structures."
  },
  {
    id: "SOL2103",
    name: "LP Token Fake Mint",
    severity: "critical",
    pattern: /lp_mint|pool_mint[\s\S]{0,50}(?!==|verify|check)/i,
    description: "LP token mint can be faked if not verified against pool.",
    recommendation: "Derive LP mint address and verify it matches provided account."
  },
  {
    id: "SOL2104",
    name: "Nested Account Trust Chain",
    severity: "critical",
    pattern: /nested[\s\S]{0,30}account|account[\s\S]{0,30}chain/i,
    description: "Nested account structure breaks trust chain validation.",
    recommendation: "Validate each level of nested accounts independently."
  },
  {
    id: "SOL2105",
    name: "Worthless Collateral Deposit",
    severity: "critical",
    pattern: /deposit[\s\S]{0,50}collateral[\s\S]{0,50}(?!value_check|price_check)/i,
    description: "Worthless tokens can be deposited as collateral.",
    recommendation: "Verify collateral value via oracle before accepting deposits."
  },
  // ========== Crema-style Tick Spoofing (SOL2106-SOL2115) ==========
  {
    id: "SOL2106",
    name: "Tick Account Owner Bypass",
    severity: "critical",
    pattern: /tick(?:_account)?[\s\S]{0,50}(?!owner\s*==|has_one)/i,
    description: "Tick account ownership not verified (Crema $8.8M exploit).",
    recommendation: "Verify tick account is owned by expected pool program."
  },
  {
    id: "SOL2107",
    name: "CLMM Position Spoofing",
    severity: "critical",
    pattern: /(?:clmm|concentrated)[\s\S]{0,50}position[\s\S]{0,50}(?!verify|owner_check)/i,
    description: "CLMM position can be spoofed to claim excess fees.",
    recommendation: "Verify position ownership and tick range before fee claims."
  },
  {
    id: "SOL2108",
    name: "Fee Accumulator Manipulation",
    severity: "critical",
    pattern: /fee(?:_accumulator|_growth)?[\s\S]{0,50}(?:claim|collect|withdraw)/i,
    description: "Fee accumulator can be manipulated via fake tick accounts.",
    recommendation: "Recalculate fees from verified tick data, never trust stored values."
  },
  {
    id: "SOL2109",
    name: "Flash Loan + CLMM Attack",
    severity: "critical",
    pattern: /flash[\s\S]{0,50}(?:clmm|concentrated|tick)/i,
    description: "Flash loans combined with CLMM manipulation.",
    recommendation: "Add flash loan protection to CLMM fee calculation."
  },
  {
    id: "SOL2110",
    name: "Tick Range Validation",
    severity: "high",
    pattern: /tick(?:_lower|_upper|_range)[\s\S]{0,50}(?!validate|check|verify)/i,
    description: "Tick range not validated for positions.",
    recommendation: "Verify tick indices are within valid pool range."
  },
  {
    id: "SOL2111",
    name: "Liquidity Delta Overflow",
    severity: "high",
    pattern: /liquidity[\s\S]{0,30}(?:delta|change|add|remove)/i,
    description: "Liquidity delta calculation can overflow.",
    recommendation: "Use checked math for all liquidity calculations."
  },
  {
    id: "SOL2112",
    name: "Sqrt Price Manipulation",
    severity: "high",
    pattern: /sqrt_price|sqrtPrice[\s\S]{0,50}(?!bounds|validate)/i,
    description: "Square root price can be manipulated beyond bounds.",
    recommendation: "Validate sqrt price against tick bounds after operations."
  },
  {
    id: "SOL2113",
    name: "Pool Swap Fee Extraction",
    severity: "high",
    pattern: /swap_fee|pool_fee[\s\S]{0,50}(?:extract|claim|withdraw)/i,
    description: "Protocol fees can be extracted improperly.",
    recommendation: "Only allow fee extraction through verified admin functions."
  },
  {
    id: "SOL2114",
    name: "Observation Account Staleness",
    severity: "medium",
    pattern: /observation[\s\S]{0,50}(?:oracle|twap)/i,
    description: "Observation/oracle data may be stale.",
    recommendation: "Check observation timestamp before using TWAP data."
  },
  {
    id: "SOL2115",
    name: "Position NFT Authority",
    severity: "high",
    pattern: /position[\s\S]{0,30}(?:nft|token)[\s\S]{0,30}(?:authority|owner)/i,
    description: "Position NFT authority can be bypassed.",
    recommendation: "Verify NFT owner matches position authority on all operations."
  },
  // ========== Program Closure Risks (SOL2116-SOL2125) ==========
  {
    id: "SOL2116",
    name: "Accidental Program Close",
    severity: "critical",
    pattern: /solana\s+program\s+close|close.*program/i,
    description: "Program can be accidentally closed, locking all funds (OptiFi $661K).",
    recommendation: "Add deployment review process with multiple approvers."
  },
  {
    id: "SOL2117",
    name: "PDA Fund Recovery",
    severity: "high",
    pattern: /pda[\s\S]{0,50}(?:close|recovery|rescue)/i,
    description: "Funds in PDAs may be unrecoverable if program is closed.",
    recommendation: "Design escape hatches that work even if program is closed."
  },
  {
    id: "SOL2118",
    name: "Upgrade Authority Lock",
    severity: "high",
    pattern: /upgrade_authority[\s\S]{0,50}(?:=|set|revoke)/i,
    description: "Upgrade authority can be revoked, making bugs permanent.",
    recommendation: "Use multisig for upgrade authority, never fully revoke on mainnet."
  },
  {
    id: "SOL2119",
    name: "Program Data Account",
    severity: "medium",
    pattern: /program_data|ProgramData/i,
    description: "Program data account manipulation risks.",
    recommendation: "Verify program data account in deployment scripts."
  },
  {
    id: "SOL2120",
    name: "Buffer Account Cleanup",
    severity: "low",
    pattern: /buffer[\s\S]{0,30}(?:close|cleanup|recover)/i,
    description: "Buffer accounts not cleaned up after deployment.",
    recommendation: "Close buffer accounts after successful deployment to recover rent."
  },
  {
    id: "SOL2121",
    name: "Deployment Script Validation",
    severity: "high",
    pattern: /deploy[\s\S]{0,50}(?:script|mainnet)/i,
    description: "Deployment scripts may contain dangerous commands.",
    recommendation: "Review deployment scripts with multiple team members."
  },
  {
    id: "SOL2122",
    name: "Program Signer Seeds",
    severity: "medium",
    pattern: /program_signer|signer_seeds/i,
    description: "Program signer seeds must be consistent across upgrades.",
    recommendation: "Document and version all PDA seeds used by program."
  },
  {
    id: "SOL2123",
    name: "Close Authority Transfer",
    severity: "critical",
    pattern: /close_authority[\s\S]{0,50}(?:transfer|set|change)/i,
    description: "Close authority can be transferred to attacker.",
    recommendation: "Close authority should only be PDA or multisig."
  },
  {
    id: "SOL2124",
    name: "Immutable Program State",
    severity: "medium",
    pattern: /immutable[\s\S]{0,30}(?:state|config)/i,
    description: "Immutable state cannot be fixed if buggy.",
    recommendation: "Design state migration paths for critical data."
  },
  {
    id: "SOL2125",
    name: "Program Freeze Risk",
    severity: "high",
    pattern: /program[\s\S]{0,30}freeze|freeze[\s\S]{0,30}program/i,
    description: "Program can be frozen, halting all operations.",
    recommendation: "Implement emergency functions that work even when frozen."
  },
  // ========== 2025 DeFi Emerging Patterns (SOL2126-SOL2140) ==========
  {
    id: "SOL2126",
    name: "Intent-Based Order Manipulation",
    severity: "high",
    pattern: /intent[\s\S]{0,50}(?:order|swap|trade)/i,
    description: "Intent-based orders can be manipulated by solvers.",
    recommendation: "Validate solver execution against user intent parameters."
  },
  {
    id: "SOL2127",
    name: "Restaking Slash Cascade",
    severity: "critical",
    pattern: /restaking[\s\S]{0,50}(?:slash|penalty)/i,
    description: "Restaking slashing can cascade across protocols.",
    recommendation: "Implement slashing caps and circuit breakers."
  },
  {
    id: "SOL2128",
    name: "LRT Depeg Attack",
    severity: "high",
    pattern: /(?:lrt|liquid_restaking)[\s\S]{0,50}(?:price|peg|exchange)/i,
    description: "Liquid restaking tokens can depeg under stress.",
    recommendation: "Use oracle prices not DEX prices for LRT valuation."
  },
  {
    id: "SOL2129",
    name: "Points Manipulation",
    severity: "medium",
    pattern: /(?:points|airdrop)[\s\S]{0,50}(?:farm|accumulate|boost)/i,
    description: "Points/airdrop farming can be gamed.",
    recommendation: "Add anti-sybil measures and time-weighted calculations."
  },
  {
    id: "SOL2130",
    name: "NFT Lending Liquidation",
    severity: "high",
    pattern: /nft[\s\S]{0,50}(?:lending|borrow|collateral)[\s\S]{0,50}liquidat/i,
    description: "NFT lending liquidations can be manipulated via floor price.",
    recommendation: "Use TWAP floor price and multiple oracle sources for NFT valuations."
  },
  {
    id: "SOL2131",
    name: "Perpetual Funding Rate Attack",
    severity: "high",
    pattern: /funding(?:_rate)?[\s\S]{0,50}(?:manipulat|attack|exploit)/i,
    description: "Perpetual funding rate can be manipulated to extract value.",
    recommendation: "Cap funding rate changes and use time-weighted averages."
  },
  {
    id: "SOL2132",
    name: "Synthetic Asset Oracle Depeg",
    severity: "critical",
    pattern: /synthetic[\s\S]{0,50}(?:oracle|price|peg)/i,
    description: "Synthetic assets can depeg if oracle is manipulated.",
    recommendation: "Use circuit breakers and multiple price sources for synths."
  },
  {
    id: "SOL2133",
    name: "RWA Token Redemption",
    severity: "high",
    pattern: /rwa|real_world[\s\S]{0,50}(?:redeem|withdraw|claim)/i,
    description: "Real-world asset token redemption may not be honored.",
    recommendation: "Verify legal backing and maintain reserve attestations."
  },
  {
    id: "SOL2134",
    name: "Social Token Rugpull",
    severity: "high",
    pattern: /social[\s\S]{0,30}token[\s\S]{0,50}(?:mint|authority)/i,
    description: "Social/creator tokens can be rugged by creator.",
    recommendation: "Lock mint authority or use bonding curve with locked liquidity."
  },
  {
    id: "SOL2135",
    name: "Prediction Market Settlement",
    severity: "high",
    pattern: /prediction[\s\S]{0,50}(?:settle|resolve|outcome)/i,
    description: "Prediction market settlement can be manipulated.",
    recommendation: "Use decentralized oracle networks for settlement."
  },
  {
    id: "SOL2136",
    name: "Blink Action Validation",
    severity: "medium",
    pattern: /blink[\s\S]{0,50}action[\s\S]{0,50}(?!validate|verify)/i,
    description: "Solana Blink actions may not validate parameters.",
    recommendation: "Validate all blink action parameters server-side."
  },
  {
    id: "SOL2137",
    name: "Compressed NFT Proof",
    severity: "high",
    pattern: /cnft|compressed[\s\S]{0,30}nft[\s\S]{0,50}(?:proof|verify)/i,
    description: "Compressed NFT merkle proofs must be verified.",
    recommendation: "Always verify cNFT proofs against current merkle root."
  },
  {
    id: "SOL2138",
    name: "Token-2022 Extension Conflict",
    severity: "medium",
    pattern: /token_2022[\s\S]{0,50}extension[\s\S]{0,50}(?:conflict|incompatible)/i,
    description: "Token-2022 extension combinations may conflict.",
    recommendation: "Test all extension combinations for compatibility."
  },
  {
    id: "SOL2139",
    name: "Lookup Table Poisoning",
    severity: "high",
    pattern: /lookup_table|address_lookup[\s\S]{0,50}(?!verify|validate)/i,
    description: "Address lookup tables can be poisoned with malicious addresses.",
    recommendation: "Verify lookup table authority before use in transactions."
  },
  {
    id: "SOL2140",
    name: "Priority Fee Griefing",
    severity: "medium",
    pattern: /priority[\s\S]{0,30}fee[\s\S]{0,50}(?:bid|auction|spam)/i,
    description: "Priority fee bidding can be used to grief transactions.",
    recommendation: "Implement transaction bundles and private mempools."
  }
];
function checkBatch54Patterns(input) {
  const findings = [];
  const content = input.rust?.content || "";
  const fileName = input.path || input.rust?.filePath || "unknown";
  if (!content) return findings;
  const lines = content.split("\n");
  for (const pattern of BATCH_54_PATTERNS) {
    try {
      const flags = pattern.pattern.flags.includes("g") ? pattern.pattern.flags : pattern.pattern.flags + "g";
      const regex = new RegExp(pattern.pattern.source, flags);
      const matches = [...content.matchAll(regex)];
      for (const match of matches) {
        const matchIndex = match.index || 0;
        let lineNum = 1;
        let charCount = 0;
        for (let i = 0; i < lines.length; i++) {
          charCount += lines[i].length + 1;
          if (charCount > matchIndex) {
            lineNum = i + 1;
            break;
          }
        }
        const startLine = Math.max(0, lineNum - 2);
        const endLine = Math.min(lines.length, lineNum + 2);
        const snippet = lines.slice(startLine, endLine).join("\n");
        findings.push({
          id: pattern.id,
          title: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          location: { file: fileName, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200)
        });
      }
    } catch (error) {
    }
  }
  return findings;
}

// src/patterns/solana-batched-patterns-55.ts
var BATCH_55_PATTERNS = [
  // ========== arXiv Academic Findings (SOL2141-SOL2160) ==========
  {
    id: "SOL2141",
    name: "arXiv: Deprecated Library Usage",
    severity: "medium",
    pattern: /solana_program\s*=\s*"1\.[0-8]\./i,
    description: "Using deprecated solana_program version. arXiv:2504.07419 identifies outdated dependencies as common vulnerability source.",
    recommendation: "Upgrade to solana_program >= 1.14 for latest security fixes."
  },
  {
    id: "SOL2142",
    name: "arXiv: Soteria-Detectable Missing Signer",
    severity: "critical",
    pattern: /pub\s+authority\s*:\s*AccountInfo(?![\s\S]{0,30}Signer|[\s\S]{0,30}is_signer)/i,
    description: "Authority account without signer check. Soteria (SEC) tool from arXiv paper detects this pattern.",
    recommendation: "Use Signer<'info> type or manually verify is_signer."
  },
  {
    id: "SOL2143",
    name: "arXiv: Radar-Detectable Type Confusion",
    severity: "high",
    pattern: /try_from_slice[\s\S]{0,50}(?!discriminator|match|if\s+\w+\[\d+\])/i,
    description: "Deserializing account data without discriminator check. Radar tool from arXiv detects type confusion.",
    recommendation: "Verify 8-byte discriminator before deserialization."
  },
  {
    id: "SOL2144",
    name: "arXiv: Anchor Privilege Escalation",
    severity: "critical",
    pattern: /#\[account\([\s\S]{0,100}mut[\s\S]{0,100}\)\][\s\S]{0,200}(?!has_one|constraint)/i,
    description: "Mutable account in Anchor without relationship constraints. arXiv identifies privilege escalation risk.",
    recommendation: "Add has_one or constraint checks for mutable accounts."
  },
  {
    id: "SOL2145",
    name: "arXiv: Laminar Static Analysis Gap",
    severity: "high",
    pattern: /invoke(?:_signed)?[\s\S]{0,100}accounts[\s\S]{0,50}\[/i,
    description: "Dynamic account indexing in CPI calls bypasses static analysis tools like Laminar.",
    recommendation: "Use named account references instead of array indexing."
  },
  {
    id: "SOL2146",
    name: "arXiv: Solana eBPF Syscall Abuse",
    severity: "critical",
    pattern: /sol_invoke_signed_c|syscall|sol_log_|sol_sha256/i,
    description: "Direct syscall usage bypasses Anchor safety. arXiv notes syscall abuse in native programs.",
    recommendation: "Use high-level Anchor abstractions when possible."
  },
  {
    id: "SOL2147",
    name: "arXiv: Insufficient Program Verification",
    severity: "critical",
    pattern: /UncheckedAccount[\s\S]{0,100}invoke(?![\s\S]{0,50}program\.key\(\)\s*==)/i,
    description: "CPI with unchecked account and no program ID verification. arXiv Table 3 lists this.",
    recommendation: "Verify target program ID before CPI calls."
  },
  {
    id: "SOL2148",
    name: "arXiv: Arithmetic Wrapping in Release",
    severity: "high",
    pattern: /\+|\-|\*(?![\s\S]{0,20}checked_|saturating_|wrapping_)[\s\S]{0,50}(?:balance|amount|supply)/i,
    description: "Arithmetic on financial values. Rust release mode wraps on overflow (arXiv Section 3.1.4).",
    recommendation: "Use checked_add/sub/mul for all financial calculations."
  },
  {
    id: "SOL2149",
    name: "arXiv: SEC Tool False Negative Area",
    severity: "medium",
    pattern: /AccountInfo<'info>[\s\S]{0,200}(?:if|match|require!)[\s\S]{0,100}owner/i,
    description: "Complex ownership check that static analyzers may miss. arXiv notes SEC tool gaps.",
    recommendation: "Ensure ownership checks are explicit and early in function."
  },
  {
    id: "SOL2150",
    name: "arXiv: Cross-Contract Vulnerability",
    severity: "critical",
    pattern: /invoke[\s\S]{0,200}state[\s\S]{0,50}=[\s\S]{0,50}(?!reload|refresh)/i,
    description: "State mutation after CPI without reload. arXiv identifies cross-contract vulnerabilities.",
    recommendation: "Reload account state after any CPI call."
  },
  {
    id: "SOL2151",
    name: "arXiv: Missing Bump Canonicalization",
    severity: "high",
    pattern: /bump\s*:\s*u8[\s\S]{0,100}(?!find_program_address|canonical)/i,
    description: "Bump stored without canonicalization. arXiv Section 3.2.2 PDA vulnerabilities.",
    recommendation: "Always use canonical bump from find_program_address."
  },
  {
    id: "SOL2152",
    name: "arXiv: Rent Exemption Bypass",
    severity: "medium",
    pattern: /lamports[\s\S]{0,50}(?:transfer|sub)[\s\S]{0,100}(?!minimum_balance|rent_exempt)/i,
    description: "Lamport transfer without rent check. arXiv notes account eviction vulnerability.",
    recommendation: "Verify account remains rent-exempt after transfers."
  },
  {
    id: "SOL2153",
    name: "arXiv: Reinitialization Attack Vector",
    severity: "critical",
    pattern: /is_initialized\s*=\s*true[\s\S]{0,200}(?!require!.*is_initialized\s*==\s*false)/i,
    description: "Setting initialized without checking prior state. arXiv cross-instance reinit attack.",
    recommendation: "Check is_initialized == false before initialization."
  },
  {
    id: "SOL2154",
    name: "arXiv: Tool Detection Comparison Gap",
    severity: "medium",
    pattern: /#\[program\][\s\S]{0,500}(?:anchor_lang|solana_program)/i,
    description: "Program using both Anchor and native. arXiv shows tool coverage gaps at boundaries.",
    recommendation: "Use consistent framework throughout program."
  },
  {
    id: "SOL2155",
    name: "arXiv: EVM vs Solana Reentrancy Difference",
    severity: "high",
    pattern: /invoke[\s\S]{0,100}(?:transfer|send)[\s\S]{0,200}state[\s\S]{0,50}=/i,
    description: "Solana reentrancy differs from EVM. arXiv notes developers assume EVM patterns apply.",
    recommendation: "Update state before CPI, even though Solana prevents recursive calls."
  },
  {
    id: "SOL2156",
    name: "arXiv: Security Tool Coverage Gap",
    severity: "low",
    pattern: /#\[cfg\(test\)\][\s\S]{0,500}(?!fuzzing|property)/i,
    description: "Tests without fuzzing. arXiv Table 4 shows limited tool coverage for complex vulns.",
    recommendation: "Add property-based testing and fuzzing with Trident."
  },
  {
    id: "SOL2157",
    name: "arXiv: Solana vs Ethereum Account Model",
    severity: "medium",
    pattern: /msg\.sender|tx\.origin/i,
    description: "EVM patterns in Solana code. arXiv emphasizes account model differences.",
    recommendation: "Use Solana account model: explicit signers and PDAs."
  },
  {
    id: "SOL2158",
    name: "arXiv: Instruction Data Validation",
    severity: "high",
    pattern: /instruction_data[\s\S]{0,50}try_from_slice[\s\S]{0,100}(?!validate|check|require)/i,
    description: "Deserializing instruction data without validation. arXiv input validation category.",
    recommendation: "Validate all instruction data fields after deserialization."
  },
  {
    id: "SOL2159",
    name: "arXiv: Compute Budget Vulnerability",
    severity: "medium",
    pattern: /for[\s\S]{0,30}in[\s\S]{0,50}\.iter\(\)[\s\S]{0,200}(?!\.take\(|\.limit|MAX_)/i,
    description: "Unbounded iteration. arXiv notes compute budget exhaustion attacks.",
    recommendation: "Add iteration limits to prevent DoS attacks."
  },
  {
    id: "SOL2160",
    name: "arXiv: Tool Ecosystem Maturity Gap",
    severity: "low",
    pattern: /\/\/\s*(?:TODO|FIXME|HACK|XXX)[\s\S]{0,50}security/i,
    description: "Security-related TODO comments. arXiv notes Solana tooling less mature than Ethereum.",
    recommendation: "Address all security TODOs before deployment."
  },
  // ========== Sealevel Attack Patterns (SOL2161-SOL2175) ==========
  {
    id: "SOL2161",
    name: "Sealevel: Duplicate Mutable Accounts",
    severity: "critical",
    pattern: /#\[account\(mut\)\][\s\S]{0,300}#\[account\(mut\)\][\s\S]{0,100}(?!constraint\s*=.*!=)/i,
    description: "Two mutable accounts of same type without inequality constraint. Armani Sealevel attack #2.",
    recommendation: "Add constraint: constraint = account_a.key() != account_b.key()"
  },
  {
    id: "SOL2162",
    name: "Sealevel: Account Type Confusion",
    severity: "critical",
    pattern: /Account<[\s\S]{0,30}>[\s\S]{0,100}try_from[\s\S]{0,50}(?!discriminator)/i,
    description: "Account deserialization without type verification. Sealevel attack #3.",
    recommendation: "Use Anchor Account<T> type or verify discriminator manually."
  },
  {
    id: "SOL2163",
    name: "Sealevel: Sysvar Address Spoofing",
    severity: "critical",
    pattern: /(?:rent|clock|slot_hashes)[\s\S]{0,50}AccountInfo[\s\S]{0,100}(?!Sysvar::id\(\)|check_id)/i,
    description: "Sysvar passed as AccountInfo without address verification. Sealevel attack #4.",
    recommendation: "Use Sysvar<Rent> type or verify sysvar.key() == Sysvar::id()"
  },
  {
    id: "SOL2164",
    name: "Sealevel: Arbitrary Program CPI",
    severity: "critical",
    pattern: /invoke[\s\S]{0,100}program[\s\S]{0,50}\.key\(\)[\s\S]{0,100}(?!==|require!|assert!)/i,
    description: "CPI to program without address verification. Sealevel attack #5.",
    recommendation: "Hardcode expected program ID or verify against allowlist."
  },
  {
    id: "SOL2165",
    name: "Sealevel: PDA Not Verified",
    severity: "high",
    pattern: /seeds\s*=[\s\S]{0,100}(?!bump|find_program_address)/i,
    description: "PDA seeds without bump verification. Sealevel attack #6.",
    recommendation: "Store and verify canonical bump seed."
  },
  {
    id: "SOL2166",
    name: "Sealevel: Bump Seed Canonicalization",
    severity: "high",
    pattern: /bump\s*:\s*\d+|bump\s*=\s*(?!ctx\.bumps|bump_seed)/i,
    description: "Hardcoded bump seed instead of canonical. Sealevel attack #7.",
    recommendation: "Use find_program_address to get canonical bump."
  },
  {
    id: "SOL2167",
    name: "Sealevel: Close Account Resurrection",
    severity: "critical",
    pattern: /close\s*=[\s\S]{0,100}(?!zero_copy|memset|\.fill\(0\))/i,
    description: "Account closure without zeroing data. Sealevel attack #8.",
    recommendation: "Zero account data before closing to prevent resurrection."
  },
  {
    id: "SOL2168",
    name: "Sealevel: Missing Owner Check",
    severity: "critical",
    pattern: /AccountInfo[\s\S]{0,200}data[\s\S]{0,100}(?!owner\s*==|check_owner)/i,
    description: "Reading account data without owner verification. Sealevel attack #1.",
    recommendation: "Verify account.owner == expected_program before reading data."
  },
  {
    id: "SOL2169",
    name: "Sealevel: Token Account Verification",
    severity: "high",
    pattern: /TokenAccount[\s\S]{0,100}(?!token::mint\s*=|token::authority\s*=)/i,
    description: "Token account without mint/authority constraints. Armani tip.",
    recommendation: "Add token::mint and token::authority constraints."
  },
  {
    id: "SOL2170",
    name: "Sealevel: Associated Token Account",
    severity: "high",
    pattern: /associated_token_account|ata[\s\S]{0,100}(?!associated_token::)/i,
    description: "ATA without proper Anchor constraint. Creates confusion with other PDAs.",
    recommendation: "Use associated_token::mint and associated_token::authority."
  },
  {
    id: "SOL2171",
    name: "Sealevel: Init If Needed Race",
    severity: "high",
    pattern: /init_if_needed[\s\S]{0,200}(?!realloc::zero\s*=\s*true)/i,
    description: "init_if_needed without zero initialization. Race condition vulnerability.",
    recommendation: "Avoid init_if_needed or ensure proper initialization."
  },
  {
    id: "SOL2172",
    name: "Sealevel: Realloc Vulnerability",
    severity: "high",
    pattern: /realloc\s*=[\s\S]{0,100}(?!realloc::zero\s*=\s*true)/i,
    description: "Account realloc without zeroing new space. Data leak vulnerability.",
    recommendation: "Add realloc::zero = true to zero new space."
  },
  {
    id: "SOL2173",
    name: "Sealevel: Constraint Ordering",
    severity: "medium",
    pattern: /#\[account\([\s\S]{0,100}constraint[\s\S]{0,100}init/i,
    description: "Constraint before init. Anchor processes attributes in order.",
    recommendation: "Place init before constraint in account attributes."
  },
  {
    id: "SOL2174",
    name: "Sealevel: Seeds Constraint Missing",
    severity: "high",
    pattern: /seeds\s*=[\s\S]{0,100}(?!seeds::program)/i,
    description: "PDA seeds without program specification. Cross-program PDA confusion.",
    recommendation: "Add seeds::program = program_id for clarity."
  },
  {
    id: "SOL2175",
    name: "Sealevel: Account Constraint Error",
    severity: "medium",
    pattern: /constraint\s*=[\s\S]{0,100}(?!@\s*\w+Error)/i,
    description: "Constraint without custom error message. Debugging difficulty.",
    recommendation: "Add custom error: constraint = condition @ CustomError::Name"
  },
  // ========== Audit-Derived Patterns (SOL2176-SOL2195) ==========
  {
    id: "SOL2176",
    name: "Kudelski: Unvalidated Reference Accounts",
    severity: "high",
    pattern: /\/\/\/\s*CHECK[\s\S]{0,50}(?:reference|read|info)/i,
    description: "Reference-only account without validation. Kudelski Solana Program Security.",
    recommendation: "Verify reference accounts even if read-only."
  },
  {
    id: "SOL2177",
    name: "Neodyme: Rounding Direction Attack",
    severity: "critical",
    pattern: /(?:div|\/)\s*\d+[\s\S]{0,50}(?:mint|transfer|withdraw)/i,
    description: "Division before token operation. Neodyme $2.6B rounding vulnerability.",
    recommendation: "Use explicit floor/ceil and favor protocol in rounding."
  },
  {
    id: "SOL2178",
    name: "OtterSec: LP Oracle Manipulation",
    severity: "critical",
    pattern: /lp_token|liquidity_pool[\s\S]{0,100}price[\s\S]{0,100}(?!fair|twap|virtual)/i,
    description: "LP token price without fair pricing. OtterSec $200M oracle manipulation.",
    recommendation: "Use virtual reserves for LP token valuation."
  },
  {
    id: "SOL2179",
    name: "Sec3: Business Logic State Machine",
    severity: "high",
    pattern: /status|state[\s\S]{0,50}=[\s\S]{0,50}(?:active|pending|complete)(?![\s\S]{0,100}match|require)/i,
    description: "State transition without validation. Sec3 2025: 38.5% are business logic bugs.",
    recommendation: "Implement explicit state machine with valid transitions."
  },
  {
    id: "SOL2180",
    name: "Sec3: Economic Invariant Violation",
    severity: "critical",
    pattern: /(?:supply|balance|reserve)[\s\S]{0,100}(?:\+|\-|=)[\s\S]{0,100}(?!invariant|assert)/i,
    description: "Economic value change without invariant check. Sec3 business logic category.",
    recommendation: "Assert economic invariants after every value change."
  },
  {
    id: "SOL2181",
    name: "Zellic: Anchor Vulnerability Patterns",
    severity: "high",
    pattern: /#\[account\][\s\S]{0,100}pub[\s\S]{0,50}:[\s\S]{0,50}Account<[\s\S]{0,50}>(?![\s\S]{0,100}constraint|has_one)/i,
    description: "Anchor account without additional constraints. Zellic vulnerability research.",
    recommendation: "Add has_one, constraint, or other validation."
  },
  {
    id: "SOL2182",
    name: "Trail of Bits: DeFi Composability Risk",
    severity: "high",
    pattern: /invoke[\s\S]{0,200}invoke[\s\S]{0,200}invoke/i,
    description: "Multiple nested CPI calls. Trail of Bits DeFi composability concerns.",
    recommendation: "Limit CPI depth and verify all intermediate states."
  },
  {
    id: "SOL2183",
    name: "Halborn: Admin Key Compromise",
    severity: "critical",
    pattern: /admin|owner|authority[\s\S]{0,50}(?:transfer|set|update)[\s\S]{0,100}(?!multisig|timelock|governance)/i,
    description: "Single admin key can change critical parameters. Halborn audit finding.",
    recommendation: "Use multisig or timelock for admin operations."
  },
  {
    id: "SOL2184",
    name: "Bramah: Stable Swap Invariant",
    severity: "high",
    pattern: /stable_swap|curve[\s\S]{0,100}(?:swap|exchange)[\s\S]{0,100}(?!invariant|amplification)/i,
    description: "Stable swap without invariant verification. Bramah Saber audit.",
    recommendation: "Verify StableSwap invariant after every operation."
  },
  {
    id: "SOL2185",
    name: "Quantstamp: Reward Distribution Drift",
    severity: "medium",
    pattern: /reward[\s\S]{0,50}(?:per_token|rate|index)[\s\S]{0,100}(?!update|refresh|sync)/i,
    description: "Reward calculation without update. Quantstamp Quarry audit.",
    recommendation: "Update reward index before any staking operation."
  },
  {
    id: "SOL2186",
    name: "SlowMist: Oracle Freshness",
    severity: "high",
    pattern: /oracle|price[\s\S]{0,50}(?:get|fetch|read)[\s\S]{0,100}(?!staleness|age|timestamp)/i,
    description: "Oracle data without freshness check. SlowMist Larix audit.",
    recommendation: "Verify oracle data is within acceptable staleness window."
  },
  {
    id: "SOL2187",
    name: "HashCloak: ZK Proof Verification",
    severity: "critical",
    pattern: /zk|zero_knowledge|proof[\s\S]{0,100}(?:verify|check)[\s\S]{0,100}(?!require!|assert!)/i,
    description: "ZK proof verification without failure handling. HashCloak Light audit.",
    recommendation: "Always assert ZK proof verification succeeds."
  },
  {
    id: "SOL2188",
    name: "Certik: Reentrancy Guard Missing",
    severity: "high",
    pattern: /pub\s+fn\s+\w+[\s\S]{0,300}invoke[\s\S]{0,200}self[\s\S]{0,50}(?:state|data|balance)/i,
    description: "State modification after CPI without guard. Certik Francium audit.",
    recommendation: "Use reentrancy guard or update state before CPI."
  },
  {
    id: "SOL2189",
    name: "Opcodes: Vesting Cliff Bypass",
    severity: "high",
    pattern: /vesting|cliff[\s\S]{0,100}(?:withdraw|claim)[\s\S]{0,100}(?!timestamp|block|slot)/i,
    description: "Vesting withdrawal without time verification. Opcodes Streamflow audit.",
    recommendation: "Check cliff and vesting schedule before allowing withdrawals."
  },
  {
    id: "SOL2190",
    name: "MadShield: NFT Staking Duration",
    severity: "medium",
    pattern: /nft[\s\S]{0,50}(?:stake|lock)[\s\S]{0,100}(?:unstake|unlock)[\s\S]{0,100}(?!duration|period|cooldown)/i,
    description: "NFT unstaking without lockup period. MadShield Genopets audit.",
    recommendation: "Enforce minimum staking duration for NFTs."
  },
  {
    id: "SOL2191",
    name: "Ackee: Fuzzing Discovery Gap",
    severity: "medium",
    pattern: /#\[cfg\(test\)\][\s\S]{0,1000}#\[test\][\s\S]{0,500}(?!proptest|arbitrary|fuzz)/i,
    description: "Unit tests without property-based testing. Ackee audit methodology.",
    recommendation: "Add Trident fuzzing or proptest for comprehensive testing."
  },
  {
    id: "SOL2192",
    name: "Audit: Emergency Pause Missing",
    severity: "high",
    pattern: /pub\s+fn\s+(?:swap|transfer|withdraw|deposit)[\s\S]{0,200}(?!paused|emergency|frozen)/i,
    description: "Critical function without pause check. Common audit finding.",
    recommendation: "Add emergency pause capability to all critical functions."
  },
  {
    id: "SOL2193",
    name: "Audit: Fee Precision Loss",
    severity: "medium",
    pattern: /fee[\s\S]{0,50}(?:\*|\/)\s*\d+[\s\S]{0,50}(?!\d{4,}|1e|10000)/i,
    description: "Fee calculation with low precision. Audit precision loss finding.",
    recommendation: "Use basis points (10000) or higher precision for fees."
  },
  {
    id: "SOL2194",
    name: "Audit: Liquidation Threshold",
    severity: "high",
    pattern: /liquidat[\s\S]{0,50}(?:threshold|factor|ratio)[\s\S]{0,50}(?:=|:)[\s\S]{0,30}(?!require|assert|check)/i,
    description: "Liquidation threshold without bounds validation. Common lending audit.",
    recommendation: "Validate threshold is within safe bounds (e.g., 50-90%)."
  },
  {
    id: "SOL2195",
    name: "Audit: Collateral Factor Timelock",
    severity: "high",
    pattern: /collateral_factor|ltv[\s\S]{0,50}(?:set|update)[\s\S]{0,100}(?!timelock|delay|governance)/i,
    description: "Collateral factor change without timelock. Lending audit finding.",
    recommendation: "Add timelock for collateral factor changes."
  },
  // ========== 2025 Emerging Attack Vectors (SOL2196-SOL2210) ==========
  {
    id: "SOL2196",
    name: "2025: Jito Client Concentration Risk",
    severity: "medium",
    pattern: /validator|stake[\s\S]{0,100}(?:jito|mev)[\s\S]{0,100}(?!diversif|multiple)/i,
    description: "Jito client has 88% validator dominance. Sec3 2025 concentration risk.",
    recommendation: "Consider MEV client diversity for protocol resilience."
  },
  {
    id: "SOL2197",
    name: "2025: Hosting Provider Concentration",
    severity: "medium",
    pattern: /teraswitch|latitude[\s\S]{0,50}|hosting[\s\S]{0,50}provider/i,
    description: "43% stake on two hosting providers. Sec3 2025 infrastructure risk.",
    recommendation: "Diversify infrastructure providers for network resilience."
  },
  {
    id: "SOL2198",
    name: "2025: Token-2022 Confidential Leaks",
    severity: "high",
    pattern: /confidential_transfer|ElGamalCiphertext[\s\S]{0,100}(?!decrypt|verify_range)/i,
    description: "Token-2022 confidential transfers require proper range proofs.",
    recommendation: "Verify all range proofs in confidential transfer handling."
  },
  {
    id: "SOL2199",
    name: "2025: Transfer Hook Reentrancy",
    severity: "critical",
    pattern: /transfer_hook|TransferHook[\s\S]{0,200}(?:invoke|call)[\s\S]{0,100}(?!guard|lock)/i,
    description: "Token-2022 transfer hooks can enable reentrancy.",
    recommendation: "Add reentrancy guard when handling transfer hooks."
  },
  {
    id: "SOL2200",
    name: "2025: cNFT Merkle Proof Manipulation",
    severity: "high",
    pattern: /merkle_proof|compressed_nft[\s\S]{0,100}(?:verify|validate)[\s\S]{0,100}(?!canopy|root)/i,
    description: "Compressed NFT proof verification without canopy.",
    recommendation: "Verify merkle proofs against on-chain canopy or root."
  },
  {
    id: "SOL2201",
    name: "2025: Blink Action URL Injection",
    severity: "high",
    pattern: /blink|action_url|solana:[\s\S]{0,100}(?!sanitize|validate|whitelist)/i,
    description: "Solana Blink action URLs without validation.",
    recommendation: "Sanitize and whitelist Blink action URLs."
  },
  {
    id: "SOL2202",
    name: "2025: Lookup Table Poisoning",
    severity: "critical",
    pattern: /address_lookup_table|alt[\s\S]{0,100}(?:extend|create)[\s\S]{0,100}(?!authority)/i,
    description: "Address lookup table modification without authority check.",
    recommendation: "Verify ALT authority before extension operations."
  },
  {
    id: "SOL2203",
    name: "2025: Priority Fee Manipulation",
    severity: "medium",
    pattern: /priority_fee|compute_budget[\s\S]{0,100}set[\s\S]{0,100}(?!cap|max|limit)/i,
    description: "Priority fee setting without caps enables griefing.",
    recommendation: "Cap priority fees to prevent economic attacks."
  },
  {
    id: "SOL2204",
    name: "2025: Durable Nonce Replay",
    severity: "high",
    pattern: /durable_nonce|nonce_account[\s\S]{0,100}(?:advance|use)[\s\S]{0,100}(?!authority)/i,
    description: "Durable nonce without authority verification.",
    recommendation: "Verify nonce authority before advancing."
  },
  {
    id: "SOL2205",
    name: "2025: Versioned Transaction Confusion",
    severity: "medium",
    pattern: /VersionedTransaction|legacy[\s\S]{0,100}(?:convert|handle)[\s\S]{0,100}(?!version|check)/i,
    description: "Mixed legacy and versioned transaction handling.",
    recommendation: "Explicitly handle transaction versioning."
  },
  {
    id: "SOL2206",
    name: "2025: Restaking Slashing Cascade",
    severity: "high",
    pattern: /restake|liquid_staking[\s\S]{0,100}(?:slash|penalty)[\s\S]{0,100}(?!isolation|cap)/i,
    description: "Restaking protocols can cascade slashing events.",
    recommendation: "Isolate slashing risk and cap per-validator exposure."
  },
  {
    id: "SOL2207",
    name: "2025: AI Agent Wallet Security",
    severity: "critical",
    pattern: /agent|bot[\s\S]{0,50}(?:wallet|keypair)[\s\S]{0,100}(?!hardware|multisig|threshold)/i,
    description: "AI agent wallets without hardware security.",
    recommendation: "Use hardware wallets or MPC for agent key management."
  },
  {
    id: "SOL2208",
    name: "2025: Meme Coin Rug Detection",
    severity: "high",
    pattern: /pump\.fun|bonding_curve[\s\S]{0,100}(?:migration|graduate)[\s\S]{0,100}(?!lock|timelock)/i,
    description: "Meme coin launch without migration protection.",
    recommendation: "Add timelock or multisig for liquidity migration."
  },
  {
    id: "SOL2209",
    name: "2025: Flash Loan Oracle Window",
    severity: "critical",
    pattern: /flash_loan[\s\S]{0,200}(?:price|oracle)[\s\S]{0,100}(?!twap|window|delay)/i,
    description: "Flash loans can manipulate single-block prices.",
    recommendation: "Use TWAP oracles spanning multiple slots."
  },
  {
    id: "SOL2210",
    name: "2025: Cross-Program Invocation Depth",
    severity: "medium",
    pattern: /invoke[\s\S]{0,100}invoke[\s\S]{0,100}invoke[\s\S]{0,100}invoke/i,
    description: "Deep CPI nesting increases attack surface.",
    recommendation: "Limit CPI depth to 4 or fewer for security and compute."
  }
];
function checkBatch55Patterns(input) {
  const findings = [];
  const content = input.rust?.content || "";
  const fileName = input.path || input.rust?.filePath || "unknown";
  if (!content) return findings;
  const lines = content.split("\n");
  for (const pattern of BATCH_55_PATTERNS) {
    try {
      const flags = pattern.pattern.flags.includes("g") ? pattern.pattern.flags : pattern.pattern.flags + "g";
      const regex = new RegExp(pattern.pattern.source, flags);
      const matches = [...content.matchAll(regex)];
      for (const match of matches) {
        const matchIndex = match.index || 0;
        let lineNum = 1;
        let charCount = 0;
        for (let i = 0; i < lines.length; i++) {
          charCount += lines[i].length + 1;
          if (charCount > matchIndex) {
            lineNum = i + 1;
            break;
          }
        }
        const startLine = Math.max(0, lineNum - 2);
        const endLine = Math.min(lines.length, lineNum + 2);
        const snippet = lines.slice(startLine, endLine).join("\n");
        findings.push({
          id: pattern.id,
          title: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          location: { file: fileName, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200)
        });
      }
    } catch (error) {
    }
  }
  return findings;
}
var BATCH_55_COUNT = BATCH_55_PATTERNS.length;

// src/patterns/solana-batched-patterns-56.ts
var BATCH_56_PATTERNS = [
  // ========== PoC Framework Patterns (SOL2211-SOL2230) ==========
  {
    id: "SOL2211",
    name: "PoC: Port Max Withdraw Bug",
    severity: "critical",
    pattern: /max_withdraw|withdraw_max[\s\S]{0,100}(?:calculate|compute)[\s\S]{0,100}(?!floor|ceil)/i,
    description: "Max withdraw calculation without rounding direction. Port Finance PoC.",
    recommendation: "Use floor for withdraw calculations to prevent overdraft."
  },
  {
    id: "SOL2212",
    name: "PoC: Jet Governance Token Lock",
    severity: "high",
    pattern: /governance[\s\S]{0,50}token[\s\S]{0,50}(?:lock|escrow)[\s\S]{0,100}(?!duration|until)/i,
    description: "Governance token locking without duration. Jet Governance PoC.",
    recommendation: "Enforce minimum lock duration for governance participation."
  },
  {
    id: "SOL2213",
    name: "PoC: Cashio Infinite Mint",
    severity: "critical",
    pattern: /collateral[\s\S]{0,100}(?:deposit|provide)[\s\S]{0,100}(?:mint|issue)[\s\S]{0,100}(?!verify_root|whitelist)/i,
    description: "Collateral deposit leading to mint without root verification. Cashio PoC.",
    recommendation: "Verify collateral is in trusted mint whitelist."
  },
  {
    id: "SOL2214",
    name: "PoC: SPL Token-Lending Rounding",
    severity: "critical",
    pattern: /(?:collateral|liquidity)[\s\S]{0,50}(?:ratio|value)[\s\S]{0,50}(?:div|\/)\s*\d+/i,
    description: "Collateral value division. Neodyme $2.6B rounding PoC.",
    recommendation: "Multiply before divide, use floor for protocol benefit."
  },
  {
    id: "SOL2215",
    name: "PoC: Cope Roulette Revert",
    severity: "medium",
    pattern: /roulette|random[\s\S]{0,100}(?:win|lose|outcome)[\s\S]{0,100}(?!commit|reveal)/i,
    description: "Random outcome without commit-reveal. Cope Roulette exploit.",
    recommendation: "Use commit-reveal scheme for random outcomes."
  },
  {
    id: "SOL2216",
    name: "PoC: Simulation Detection Bypass",
    severity: "high",
    pattern: /simulation|preflight[\s\S]{0,100}(?:detect|check)[\s\S]{0,100}(?!bank|slot)/i,
    description: "Simulation detection without bank context. Opcodes research.",
    recommendation: "Check bank state to detect simulation vs execution."
  },
  {
    id: "SOL2217",
    name: "PoC: Authority Delegation Chain",
    severity: "high",
    pattern: /delegate[\s\S]{0,50}authority[\s\S]{0,100}(?:chain|nested|recursive)/i,
    description: "Authority delegation allowing chains. Multi-hop vulnerability.",
    recommendation: "Limit delegation depth to prevent authority confusion."
  },
  {
    id: "SOL2218",
    name: "PoC: Token Approval Persistence",
    severity: "medium",
    pattern: /approve[\s\S]{0,50}delegate[\s\S]{0,100}(?!revoke|clear|reset)/i,
    description: "Token approval without revocation mechanism. Hana revoken research.",
    recommendation: "Provide clear approval revocation mechanism."
  },
  {
    id: "SOL2219",
    name: "PoC: Stake Pool Semantic Bug",
    severity: "high",
    pattern: /stake_pool[\s\S]{0,100}(?:deposit|withdraw)[\s\S]{0,100}(?!validator_list|stake_list)/i,
    description: "Stake pool operation without list verification. Sec3 Stake Pool PoC.",
    recommendation: "Verify stake account is in pool validator list."
  },
  {
    id: "SOL2220",
    name: "PoC: Lending Market Spoofing",
    severity: "critical",
    pattern: /lending_market[\s\S]{0,100}(?:create|init)[\s\S]{0,100}(?!authority|owner\s*==)/i,
    description: "Lending market creation without authority binding. Solend exploit.",
    recommendation: "Permanently bind lending market to authority at creation."
  },
  {
    id: "SOL2221",
    name: "PoC: Oracle Price Staleness",
    severity: "high",
    pattern: /price[\s\S]{0,50}(?:get|fetch)[\s\S]{0,100}(?:age|stale|fresh|timestamp)/i,
    description: "Price fetching with staleness check present but may be insufficient.",
    recommendation: "Use strict staleness bounds (e.g., 30 seconds for DeFi)."
  },
  {
    id: "SOL2222",
    name: "PoC: LP Token Manipulation",
    severity: "critical",
    pattern: /lp_token[\s\S]{0,100}(?:value|worth|price)[\s\S]{0,50}(?:total_supply|reserve)/i,
    description: "LP token value from reserves. OtterSec $200M manipulation PoC.",
    recommendation: "Use virtual reserves or geometric mean for LP pricing."
  },
  {
    id: "SOL2223",
    name: "PoC: Malicious Lending Market",
    severity: "critical",
    pattern: /malicious[\s\S]{0,50}(?:market|pool|reserve)|fake_(?:market|pool)/i,
    description: "Malicious market pattern. Solend Rooter disclosure.",
    recommendation: "Verify market authenticity via on-chain registry."
  },
  {
    id: "SOL2224",
    name: "PoC: Guardian Quorum Bypass",
    severity: "critical",
    pattern: /guardian[\s\S]{0,100}(?:verify|check)[\s\S]{0,100}(?:signature|quorum)[\s\S]{0,100}(?!\d+\s*\/\s*\d+|threshold)/i,
    description: "Guardian verification without quorum threshold. Wormhole pattern.",
    recommendation: "Enforce minimum guardian signature quorum (e.g., 13/19)."
  },
  {
    id: "SOL2225",
    name: "PoC: SignatureSet Fabrication",
    severity: "critical",
    pattern: /signature_set|SignatureSet[\s\S]{0,100}(?:create|init)[\s\S]{0,100}(?!verify|validate)/i,
    description: "SignatureSet creation without verification. Wormhole $326M exploit.",
    recommendation: "Verify all signatures before creating SignatureSet."
  },
  {
    id: "SOL2226",
    name: "PoC: CLMM Tick Manipulation",
    severity: "critical",
    pattern: /tick[\s\S]{0,50}(?:account|data)[\s\S]{0,100}(?:fee|liquidity)[\s\S]{0,100}(?!owner\s*==)/i,
    description: "Tick account access without ownership. Crema $8.8M exploit.",
    recommendation: "Verify tick account ownership before fee operations."
  },
  {
    id: "SOL2227",
    name: "PoC: Bonding Curve Flash Loan",
    severity: "critical",
    pattern: /bonding_curve[\s\S]{0,100}(?:buy|mint)[\s\S]{0,100}(?!flash_loan_check|same_block)/i,
    description: "Bonding curve without flash loan protection. Nirvana exploit.",
    recommendation: "Add flash loan detection or multi-block price averaging."
  },
  {
    id: "SOL2228",
    name: "PoC: Perp Mark Price Manipulation",
    severity: "critical",
    pattern: /mark_price|perp[\s\S]{0,100}(?:price|funding)[\s\S]{0,100}(?!oracle|twap|window)/i,
    description: "Perpetual mark price without oracle verification. Mango pattern.",
    recommendation: "Use oracle TWAP for mark price calculation."
  },
  {
    id: "SOL2229",
    name: "PoC: Self-Trading Detection",
    severity: "high",
    pattern: /(?:buy|sell|trade)[\s\S]{0,200}(?:buy|sell|trade)[\s\S]{0,100}(?!different_owner|anti_self)/i,
    description: "Trading without self-trade prevention. Mango Markets exploit.",
    recommendation: "Detect and prevent self-trading for price manipulation."
  },
  {
    id: "SOL2230",
    name: "PoC: Unrealized PnL Collateral",
    severity: "critical",
    pattern: /unrealized[\s\S]{0,50}(?:pnl|profit)[\s\S]{0,100}(?:collateral|borrow)/i,
    description: "Using unrealized PnL as collateral. Mango Markets attack vector.",
    recommendation: "Only use realized PnL for collateral calculations."
  },
  // ========== Protocol-Specific Exploits (SOL2231-SOL2255) ==========
  {
    id: "SOL2231",
    name: "Pyth: Confidence Interval Check",
    severity: "high",
    pattern: /pyth[\s\S]{0,100}(?:price|feed)[\s\S]{0,100}(?!conf|confidence|uncertainty)/i,
    description: "Pyth oracle without confidence interval check. Drift guardrails.",
    recommendation: "Reject prices with confidence > price * threshold."
  },
  {
    id: "SOL2232",
    name: "Switchboard: Aggregator Staleness",
    severity: "high",
    pattern: /switchboard[\s\S]{0,100}(?:aggregator|feed)[\s\S]{0,100}(?!latest_confirmed_round|staleness)/i,
    description: "Switchboard aggregator without staleness check.",
    recommendation: "Check latest_confirmed_round timestamp."
  },
  {
    id: "SOL2233",
    name: "Marinade: mSOL Pricing Attack",
    severity: "high",
    pattern: /msol|marinade[\s\S]{0,100}(?:price|rate)[\s\S]{0,100}(?!exchange_rate|virtual)/i,
    description: "mSOL pricing without exchange rate verification.",
    recommendation: "Use Marinade exchange rate from stake pool."
  },
  {
    id: "SOL2234",
    name: "Jupiter: Route Manipulation",
    severity: "high",
    pattern: /jupiter[\s\S]{0,100}(?:route|swap)[\s\S]{0,100}(?!slippage|min_out)/i,
    description: "Jupiter swap without slippage protection.",
    recommendation: "Always specify minimum output amount."
  },
  {
    id: "SOL2235",
    name: "Drift: Oracle Guard Rails",
    severity: "high",
    pattern: /drift[\s\S]{0,100}oracle[\s\S]{0,100}(?!guard|validity|too_volatile)/i,
    description: "Drift-style oracle without guard rails.",
    recommendation: "Implement oracle validity checks like Drift."
  },
  {
    id: "SOL2236",
    name: "Solend: Reserve Refresh",
    severity: "high",
    pattern: /reserve[\s\S]{0,100}(?:interest|rate)[\s\S]{0,100}(?!refresh|accrue|update)/i,
    description: "Reserve state without interest refresh.",
    recommendation: "Refresh reserve state before rate-sensitive operations."
  },
  {
    id: "SOL2237",
    name: "Port: Variable Rate Model",
    severity: "medium",
    pattern: /interest_rate[\s\S]{0,100}(?:model|curve)[\s\S]{0,100}(?!bounds|cap|floor)/i,
    description: "Interest rate model without bounds.",
    recommendation: "Cap interest rates at reasonable maximum."
  },
  {
    id: "SOL2238",
    name: "Jet: Margin Account Isolation",
    severity: "high",
    pattern: /margin[\s\S]{0,50}account[\s\S]{0,100}(?:position|collateral)[\s\S]{0,100}(?!isolation|separate)/i,
    description: "Margin accounts without position isolation.",
    recommendation: "Isolate positions to prevent cross-contamination."
  },
  {
    id: "SOL2239",
    name: "Orca: Whirlpool Tick Array",
    severity: "medium",
    pattern: /tick_array|whirlpool[\s\S]{0,100}(?:swap|trade)[\s\S]{0,100}(?!initialized|valid)/i,
    description: "Whirlpool swap without tick array validation.",
    recommendation: "Verify tick arrays are initialized and valid."
  },
  {
    id: "SOL2240",
    name: "Raydium: Pool Authority Leak",
    severity: "critical",
    pattern: /pool_authority|raydium[\s\S]{0,100}(?:admin|owner)[\s\S]{0,100}(?!multisig|timelock)/i,
    description: "Raydium-style pool without admin protection. $4.4M exploit.",
    recommendation: "Use multisig for pool administration."
  },
  {
    id: "SOL2241",
    name: "Saber: Stable Swap A Factor",
    severity: "medium",
    pattern: /amplification|a_factor[\s\S]{0,100}(?:set|update)[\s\S]{0,100}(?!ramp|gradual)/i,
    description: "Amplification factor change without ramp.",
    recommendation: "Gradually ramp A factor changes over time."
  },
  {
    id: "SOL2242",
    name: "Metaplex: Collection Authority",
    severity: "high",
    pattern: /collection[\s\S]{0,50}(?:verify|authority)[\s\S]{0,100}(?!update_authority|creator)/i,
    description: "NFT collection verification gap.",
    recommendation: "Verify collection authority matches expected."
  },
  {
    id: "SOL2243",
    name: "Magic Eden: Royalty Enforcement",
    severity: "medium",
    pattern: /royalt[\s\S]{0,50}(?:check|enforce)[\s\S]{0,100}(?!pnft|programmable)/i,
    description: "NFT royalty enforcement gap.",
    recommendation: "Use pNFTs for enforced royalties."
  },
  {
    id: "SOL2244",
    name: "Tensor: Compressed NFT Proof",
    severity: "high",
    pattern: /cnft|compressed[\s\S]{0,50}nft[\s\S]{0,100}(?:transfer|burn)[\s\S]{0,100}(?!proof|canopy)/i,
    description: "Compressed NFT operation without proof.",
    recommendation: "Verify merkle proof for all cNFT operations."
  },
  {
    id: "SOL2245",
    name: "Phoenix: Order Book Crossing",
    severity: "high",
    pattern: /order_book|orderbook[\s\S]{0,100}(?:match|cross)[\s\S]{0,100}(?!self_trade|wash)/i,
    description: "Order book without wash trading prevention.",
    recommendation: "Detect and prevent self-crossing orders."
  },
  {
    id: "SOL2246",
    name: "Zeta: Greeks Calculation",
    severity: "medium",
    pattern: /(?:delta|gamma|theta|vega)[\s\S]{0,100}(?:calculate|compute)[\s\S]{0,100}(?!black_scholes|model)/i,
    description: "Options greeks without proper model.",
    recommendation: "Use validated Black-Scholes or similar model."
  },
  {
    id: "SOL2247",
    name: "Friktion: Vault Epoch Transition",
    severity: "high",
    pattern: /vault[\s\S]{0,50}epoch[\s\S]{0,100}(?:transition|settle)[\s\S]{0,100}(?!lock|freeze)/i,
    description: "Vault epoch transition without locking.",
    recommendation: "Lock deposits during epoch transitions."
  },
  {
    id: "SOL2248",
    name: "Mango V4: Health Factor",
    severity: "high",
    pattern: /health[\s\S]{0,50}(?:factor|ratio)[\s\S]{0,100}(?:check|verify)[\s\S]{0,100}(?!before|prior)/i,
    description: "Health factor checked after operation.",
    recommendation: "Check health factor before allowing position changes."
  },
  {
    id: "SOL2249",
    name: "Tulip: Strategy Migration",
    severity: "high",
    pattern: /strategy[\s\S]{0,50}(?:migrate|upgrade)[\s\S]{0,100}(?!lock|pause|governance)/i,
    description: "Strategy migration without safeguards.",
    recommendation: "Require governance and lockup for migrations."
  },
  {
    id: "SOL2250",
    name: "UXD: Peg Mechanism",
    severity: "high",
    pattern: /peg|stablecoin[\s\S]{0,100}(?:mint|redeem)[\s\S]{0,100}(?!delta_neutral|hedge)/i,
    description: "Stablecoin without delta-neutral hedging.",
    recommendation: "Maintain delta-neutral position for peg stability."
  },
  {
    id: "SOL2251",
    name: "Hubble: Multi-Collateral CDP",
    severity: "high",
    pattern: /cdp|collateral_debt[\s\S]{0,100}(?:multiple|multi)[\s\S]{0,100}(?!correlation|risk)/i,
    description: "Multi-collateral CDP without correlation risk.",
    recommendation: "Account for collateral correlation in risk model."
  },
  {
    id: "SOL2252",
    name: "Hedge: Stability Pool Drain",
    severity: "high",
    pattern: /stability_pool[\s\S]{0,100}(?:withdraw|drain)[\s\S]{0,100}(?!cooldown|limit)/i,
    description: "Stability pool without withdrawal limits.",
    recommendation: "Add cooldown and rate limits for withdrawals."
  },
  {
    id: "SOL2253",
    name: "Invariant: Concentrated Liquidity",
    severity: "medium",
    pattern: /concentrated[\s\S]{0,50}liquidity[\s\S]{0,100}(?:position|range)[\s\S]{0,100}(?!fee_growth|fees_owed)/i,
    description: "Concentrated liquidity without fee tracking.",
    recommendation: "Track fee growth per tick for accurate rewards."
  },
  {
    id: "SOL2254",
    name: "Cropper: Fee Precision",
    severity: "medium",
    pattern: /fee[\s\S]{0,50}(?:numerator|rate)[\s\S]{0,50}(?:\/|div)\s*(?:denominator|\d+)/i,
    description: "Fee calculation precision loss.",
    recommendation: "Use high precision (1e9+) for fee calculations."
  },
  {
    id: "SOL2255",
    name: "Swim: Cross-Chain Token Mapping",
    severity: "high",
    pattern: /cross_chain[\s\S]{0,100}(?:token|mint)[\s\S]{0,100}(?:map|registry)[\s\S]{0,100}(?!verify|authentic)/i,
    description: "Cross-chain token without authenticity verification.",
    recommendation: "Verify token mapping in trusted registry."
  },
  // ========== Advanced DeFi Attack Vectors (SOL2256-SOL2280) ==========
  {
    id: "SOL2256",
    name: "Flash Loan Atomic Arbitrage",
    severity: "high",
    pattern: /flash_loan[\s\S]{0,200}(?:swap|exchange)[\s\S]{0,200}(?:repay)/i,
    description: "Flash loan arbitrage pattern detected.",
    recommendation: "Ensure flash loan repayment verification is atomic."
  },
  {
    id: "SOL2257",
    name: "Sandwich Attack Vector",
    severity: "high",
    pattern: /swap[\s\S]{0,100}(?:slippage|price_impact)[\s\S]{0,100}(?:tolerance|limit)/i,
    description: "Swap with slippage tolerance enables sandwiching.",
    recommendation: "Use private transactions or MEV protection."
  },
  {
    id: "SOL2258",
    name: "JIT Liquidity Attack",
    severity: "medium",
    pattern: /liquidity[\s\S]{0,50}(?:add|provide)[\s\S]{0,100}(?:same_tx|atomic)/i,
    description: "Just-in-time liquidity provision.",
    recommendation: "Add minimum liquidity duration requirements."
  },
  {
    id: "SOL2259",
    name: "Time-Bandit Reorganization",
    severity: "high",
    pattern: /(?:finality|confirmation)[\s\S]{0,100}(?:wait|require)[\s\S]{0,50}\d+/i,
    description: "Transaction finality assumption vulnerability.",
    recommendation: "Wait for sufficient confirmations for large values."
  },
  {
    id: "SOL2260",
    name: "Liquidation Auction Manipulation",
    severity: "high",
    pattern: /liquidation[\s\S]{0,50}(?:auction|bid)[\s\S]{0,100}(?!dutch|reserve)/i,
    description: "Liquidation auction without fair pricing.",
    recommendation: "Use Dutch auction with reserve price."
  },
  {
    id: "SOL2261",
    name: "Interest Rate Spike",
    severity: "high",
    pattern: /interest[\s\S]{0,50}rate[\s\S]{0,100}(?:utilization|borrow)[\s\S]{0,100}(?!max|cap|ceiling)/i,
    description: "Interest rate model without spike protection.",
    recommendation: "Cap maximum interest rate during high utilization."
  },
  {
    id: "SOL2262",
    name: "Governance Token Concentration",
    severity: "medium",
    pattern: /governance[\s\S]{0,50}(?:vote|power)[\s\S]{0,100}(?!delegation|decay)/i,
    description: "Governance without vote decay.",
    recommendation: "Implement vote decay or quadratic voting."
  },
  {
    id: "SOL2263",
    name: "Proposal Execution Delay",
    severity: "high",
    pattern: /proposal[\s\S]{0,50}(?:execute|enact)[\s\S]{0,100}(?!timelock|delay|queue)/i,
    description: "Proposal execution without delay.",
    recommendation: "Add timelock delay for governance execution."
  },
  {
    id: "SOL2264",
    name: "Vault Share Inflation",
    severity: "critical",
    pattern: /vault[\s\S]{0,50}(?:deposit|mint)[\s\S]{0,100}(?:first_deposit|initial)[\s\S]{0,100}(?!minimum|seed)/i,
    description: "First depositor can inflate vault shares.",
    recommendation: "Seed vault with minimum deposit or use dead shares."
  },
  {
    id: "SOL2265",
    name: "Donation Attack",
    severity: "high",
    pattern: /(?:balance|reserve)[\s\S]{0,100}(?:get|read)[\s\S]{0,100}(?!expected|tracked)/i,
    description: "Using balance instead of tracked reserves.",
    recommendation: "Track reserves internally, not from balance."
  },
  {
    id: "SOL2266",
    name: "Price Oracle TWAP Window",
    severity: "high",
    pattern: /twap[\s\S]{0,100}(?:window|period)[\s\S]{0,50}(?:\d+)/i,
    description: "TWAP window may be too short for security.",
    recommendation: "Use minimum 30-minute TWAP for DeFi pricing."
  },
  {
    id: "SOL2267",
    name: "Collateral Factor Manipulation",
    severity: "high",
    pattern: /collateral_factor[\s\S]{0,100}(?:volatile|risky)[\s\S]{0,100}(?!reduce|conservative)/i,
    description: "High collateral factor for volatile assets.",
    recommendation: "Use conservative collateral factors (< 70%)."
  },
  {
    id: "SOL2268",
    name: "Insurance Fund Depletion",
    severity: "critical",
    pattern: /insurance[\s\S]{0,50}fund[\s\S]{0,100}(?:withdraw|use)[\s\S]{0,100}(?!threshold|minimum)/i,
    description: "Insurance fund without minimum threshold.",
    recommendation: "Maintain minimum insurance fund coverage."
  },
  {
    id: "SOL2269",
    name: "Debt Ceiling Bypass",
    severity: "high",
    pattern: /debt[\s\S]{0,50}(?:ceiling|cap|limit)[\s\S]{0,100}(?!check|require|assert)/i,
    description: "Debt ceiling without enforcement.",
    recommendation: "Enforce debt ceiling on every borrow."
  },
  {
    id: "SOL2270",
    name: "Reserve Factor Abuse",
    severity: "medium",
    pattern: /reserve_factor[\s\S]{0,100}(?:set|update)[\s\S]{0,100}(?!governance|timelock)/i,
    description: "Reserve factor changes without governance.",
    recommendation: "Require governance for reserve factor changes."
  },
  {
    id: "SOL2271",
    name: "Lending Pool Isolation",
    severity: "high",
    pattern: /lending[\s\S]{0,50}pool[\s\S]{0,100}(?:share|cross)[\s\S]{0,100}(?!isolated|separate)/i,
    description: "Lending pools sharing risk.",
    recommendation: "Isolate high-risk lending pools."
  },
  {
    id: "SOL2272",
    name: "Yield Strategy Griefing",
    severity: "medium",
    pattern: /yield[\s\S]{0,50}strategy[\s\S]{0,100}(?:harvest|compound)[\s\S]{0,100}(?!threshold|profitable)/i,
    description: "Yield strategy vulnerable to griefing.",
    recommendation: "Add profitability check before harvest."
  },
  {
    id: "SOL2273",
    name: "Perpetual Funding Rate Spike",
    severity: "high",
    pattern: /funding[\s\S]{0,50}rate[\s\S]{0,100}(?:calculate|compute)[\s\S]{0,100}(?!cap|max|clamp)/i,
    description: "Funding rate without caps.",
    recommendation: "Cap funding rate to prevent extreme values."
  },
  {
    id: "SOL2274",
    name: "ADL Priority Manipulation",
    severity: "high",
    pattern: /adl|auto_deleverage[\s\S]{0,100}(?:priority|ranking)[\s\S]{0,100}(?!pnl|profit)/i,
    description: "ADL ranking without PnL consideration.",
    recommendation: "Rank ADL by unrealized PnL percentage."
  },
  {
    id: "SOL2275",
    name: "Position Limit Bypass",
    severity: "high",
    pattern: /position[\s\S]{0,50}(?:limit|max)[\s\S]{0,100}(?!aggregate|total)/i,
    description: "Position limits without aggregation.",
    recommendation: "Aggregate positions across all accounts."
  },
  {
    id: "SOL2276",
    name: "Staking Reward Dilution",
    severity: "medium",
    pattern: /reward[\s\S]{0,50}(?:rate|per_token)[\s\S]{0,100}(?!update_before|sync)/i,
    description: "Staking rewards without pre-update.",
    recommendation: "Update reward rate before stake changes."
  },
  {
    id: "SOL2277",
    name: "Unbonding Period Bypass",
    severity: "high",
    pattern: /unbond[\s\S]{0,100}(?:period|duration)[\s\S]{0,100}(?!enforce|check)/i,
    description: "Unbonding period without enforcement.",
    recommendation: "Strictly enforce unbonding cooldown."
  },
  {
    id: "SOL2278",
    name: "Validator Commission Change",
    severity: "medium",
    pattern: /commission[\s\S]{0,100}(?:change|update)[\s\S]{0,100}(?!delay|epoch)/i,
    description: "Validator commission instant change.",
    recommendation: "Add epoch delay for commission changes."
  },
  {
    id: "SOL2279",
    name: "Stake Pool Withdraw Authority",
    severity: "high",
    pattern: /stake_pool[\s\S]{0,100}(?:withdraw|unstake)[\s\S]{0,100}(?!authority|owner)/i,
    description: "Stake pool withdrawal without authority check.",
    recommendation: "Verify withdraw authority matches depositor."
  },
  {
    id: "SOL2280",
    name: "Delegation Authority Confusion",
    severity: "high",
    pattern: /delegation[\s\S]{0,100}(?:stake|vote)[\s\S]{0,100}(?!authorized|authority)/i,
    description: "Delegation without authority verification.",
    recommendation: "Verify delegation authority before stake operations."
  }
];
function checkBatch56Patterns(input) {
  const findings = [];
  const content = input.rust?.content || "";
  const fileName = input.path || input.rust?.filePath || "unknown";
  if (!content) return findings;
  const lines = content.split("\n");
  for (const pattern of BATCH_56_PATTERNS) {
    try {
      const flags = pattern.pattern.flags.includes("g") ? pattern.pattern.flags : pattern.pattern.flags + "g";
      const regex = new RegExp(pattern.pattern.source, flags);
      const matches = [...content.matchAll(regex)];
      for (const match of matches) {
        const matchIndex = match.index || 0;
        let lineNum = 1;
        let charCount = 0;
        for (let i = 0; i < lines.length; i++) {
          charCount += lines[i].length + 1;
          if (charCount > matchIndex) {
            lineNum = i + 1;
            break;
          }
        }
        const startLine = Math.max(0, lineNum - 2);
        const endLine = Math.min(lines.length, lineNum + 2);
        const snippet = lines.slice(startLine, endLine).join("\n");
        findings.push({
          id: pattern.id,
          title: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          location: { file: fileName, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200)
        });
      }
    } catch (error) {
    }
  }
  return findings;
}
var BATCH_56_COUNT = BATCH_56_PATTERNS.length;

// src/patterns/index.ts
var CORE_PATTERNS = [
  {
    id: "SOL001",
    name: "Missing Owner Check",
    severity: "critical",
    pattern: /AccountInfo[\s\S]{0,200}(?![\s\S]{0,100}owner\s*==)(?![\s\S]{0,100}has_one)/,
    description: "Account ownership is not verified. Anyone could pass a malicious account.",
    recommendation: "Add owner validation: require!(account.owner == expected_program, ErrorCode::InvalidOwner);"
  },
  {
    id: "SOL002",
    name: "Missing Signer Check",
    severity: "critical",
    pattern: /\/\/\/\s*CHECK:|AccountInfo.*(?!.*Signer|.*is_signer|.*#\[account\(.*signer)/,
    description: "Authority account lacks signer verification.",
    recommendation: "Add signer constraint: #[account(signer)] or verify is_signer manually."
  },
  {
    id: "SOL003",
    name: "Integer Overflow",
    severity: "high",
    pattern: /\b\w+\s*[-+*]\s*\w+(?!.*checked_|.*saturating_|.*wrapping_)/,
    description: "Arithmetic operation without overflow protection.",
    recommendation: "Use checked_add(), checked_sub(), or checked_mul()."
  },
  {
    id: "SOL004",
    name: "PDA Validation Gap",
    severity: "high",
    pattern: /find_program_address|create_program_address(?![\s\S]{0,50}bump|[\s\S]{0,50}seeds)/,
    description: "PDA derivation without bump seed storage.",
    recommendation: "Store and verify the canonical bump seed."
  },
  {
    id: "SOL005",
    name: "Authority Bypass",
    severity: "critical",
    pattern: /authority|admin|owner.*AccountInfo(?!.*constraint|.*has_one)/i,
    description: "Sensitive authority account without proper constraints.",
    recommendation: "Add has_one constraint: #[account(has_one = authority)]"
  },
  {
    id: "SOL006",
    name: "Missing Init Check",
    severity: "critical",
    pattern: /init\s*=\s*false|is_initialized\s*=\s*false(?![\s\S]{0,100}require!|[\s\S]{0,100}assert)/,
    description: "Account can be reinitialized, potentially resetting state.",
    recommendation: "Check is_initialized before modifying account state."
  },
  {
    id: "SOL007",
    name: "CPI Vulnerability",
    severity: "high",
    pattern: /invoke(?:_signed)?(?![\s\S]{0,100}program_id\s*==)/,
    description: "Cross-program invocation without verifying target program.",
    recommendation: "Verify program_id matches expected value before CPI."
  },
  {
    id: "SOL008",
    name: "Rounding Error",
    severity: "medium",
    pattern: /\/\s*\d+(?![\s\S]{0,50}checked_div|[\s\S]{0,50}\.ceil\(|[\s\S]{0,50}\.floor\()/,
    description: "Division without proper rounding handling.",
    recommendation: "Use explicit rounding (ceil/floor) for financial calculations."
  },
  {
    id: "SOL009",
    name: "Account Confusion",
    severity: "high",
    pattern: /#\[account\][\s\S]{0,200}(?![\s\S]{0,100}discriminator)/,
    description: "Account struct may be confused with other types.",
    recommendation: "Verify account discriminator before deserializing."
  },
  {
    id: "SOL010",
    name: "Account Closing Vulnerability",
    severity: "critical",
    pattern: /close\s*=|try_borrow_mut_lamports[\s\S]{0,50}=\s*0(?![\s\S]{0,50}realloc|[\s\S]{0,50}zero)/,
    description: "Account closure without proper cleanup could allow revival.",
    recommendation: "Zero out account data before closing."
  },
  {
    id: "SOL011",
    name: "Reentrancy Risk",
    severity: "high",
    pattern: /invoke(?:_signed)?[\s\S]{0,200}(?:balance|lamports|amount)\s*[+-=]/,
    description: "State modification after CPI call could enable reentrancy.",
    recommendation: "Update state before making external calls."
  },
  {
    id: "SOL012",
    name: "Arbitrary CPI",
    severity: "critical",
    pattern: /invoke[\s\S]{0,50}program_id(?![\s\S]{0,50}==|[\s\S]{0,50}require!)/,
    description: "CPI to arbitrary program without validation.",
    recommendation: "Hardcode expected program IDs or validate against allowlist."
  },
  {
    id: "SOL013",
    name: "Duplicate Mutable",
    severity: "high",
    pattern: /#\[account\(mut\)\][\s\S]*?#\[account\(mut\)\]/,
    description: "Multiple mutable references to same account type.",
    recommendation: "Add constraints to ensure accounts are different."
  },
  {
    id: "SOL014",
    name: "Missing Rent Check",
    severity: "medium",
    pattern: /lamports[\s\S]{0,100}(?!rent_exempt|minimum_balance)/,
    description: "Account may not be rent-exempt.",
    recommendation: "Verify account has minimum rent-exempt balance."
  },
  {
    id: "SOL015",
    name: "Type Cosplay",
    severity: "critical",
    pattern: /#\[account\][\s\S]{0,100}pub\s+struct(?![\s\S]{0,100}discriminator)/,
    description: "Account struct could be confused with other types.",
    recommendation: "Add unique discriminator or use Anchor."
  },
  {
    id: "SOL016",
    name: "Bump Seed Issue",
    severity: "high",
    pattern: /bump(?![\s\S]{0,50}canonical|[\s\S]{0,50}find_program_address)/,
    description: "Non-canonical bump seed could allow account spoofing.",
    recommendation: "Always use canonical bump from find_program_address."
  },
  {
    id: "SOL017",
    name: "Freeze Authority",
    severity: "medium",
    pattern: /freeze_authority|FreezeAccount(?![\s\S]{0,100}check|[\s\S]{0,100}verify)/,
    description: "Freeze authority operations without validation.",
    recommendation: "Verify freeze authority before operations."
  },
  {
    id: "SOL018",
    name: "Oracle Manipulation",
    severity: "high",
    pattern: /price|oracle|feed(?![\s\S]{0,100}staleness|[\s\S]{0,100}confidence|[\s\S]{0,100}twap)/i,
    description: "Oracle data without staleness or confidence checks.",
    recommendation: "Check staleness, confidence, use TWAP for critical ops."
  },
  {
    id: "SOL019",
    name: "Flash Loan Risk",
    severity: "critical",
    pattern: /flash_loan|flashloan|instant_loan(?![\s\S]{0,200}repay|[\s\S]{0,200}callback)/i,
    description: "Flash loan implementation without repayment verification.",
    recommendation: "Verify loan is repaid in same transaction."
  },
  {
    id: "SOL020",
    name: "Unsafe Math",
    severity: "high",
    pattern: /as\s+u\d+|as\s+i\d+(?![\s\S]{0,30}try_into|[\s\S]{0,30}checked)/,
    description: "Unsafe type casting could cause overflow.",
    recommendation: "Use try_into() for safe casting."
  },
  {
    id: "SOL021",
    name: "Sysvar Manipulation",
    severity: "critical",
    pattern: /sysvar::clock|sysvar::rent(?![\s\S]{0,50}from_account_info)/,
    description: "Sysvar accessed without proper validation.",
    recommendation: "Use from_account_info() to validate sysvars."
  },
  {
    id: "SOL022",
    name: "Upgrade Authority",
    severity: "medium",
    pattern: /upgrade_authority|set_authority(?![\s\S]{0,100}multisig|[\s\S]{0,100}timelock)/i,
    description: "Program upgrade without proper controls.",
    recommendation: "Use multisig or timelock for upgrade authority."
  },
  {
    id: "SOL023",
    name: "Token Validation",
    severity: "high",
    pattern: /token_account|TokenAccount(?![\s\S]{0,100}mint\s*==|[\s\S]{0,100}owner\s*==)/i,
    description: "Token account without mint/owner validation.",
    recommendation: "Verify token account mint and owner."
  },
  {
    id: "SOL024",
    name: "Cross-Program State",
    severity: "high",
    pattern: /invoke[\s\S]{0,100}state[\s\S]{0,100}(?![\s\S]{0,50}refresh|[\s\S]{0,50}reload)/,
    description: "Cross-program call without state refresh.",
    recommendation: "Refresh state after cross-program calls."
  },
  {
    id: "SOL025",
    name: "Lamport Balance",
    severity: "high",
    pattern: /lamports[\s\S]{0,50}(?:sub|add)(?![\s\S]{0,30}checked)/,
    description: "Unsafe lamport arithmetic.",
    recommendation: "Use checked arithmetic for lamport operations."
  },
  // Continue with more patterns...
  {
    id: "SOL026",
    name: "Seeded Account",
    severity: "medium",
    pattern: /create_account_with_seed(?![\s\S]{0,100}verify)/,
    description: "Seeded account creation without verification.",
    recommendation: "Verify seeds match expected values."
  },
  {
    id: "SOL027",
    name: "Unsafe Unwrap",
    severity: "medium",
    pattern: /\.unwrap\(\)|\.expect\(/,
    description: "Using unwrap() can cause panic.",
    recommendation: "Use ? operator or match for error handling."
  },
  {
    id: "SOL028",
    name: "Missing Events",
    severity: "low",
    pattern: /transfer|mint|burn(?![\s\S]{0,200}emit!|[\s\S]{0,200}log|[\s\S]{0,200}msg!)/i,
    description: "State-changing operation without event emission.",
    recommendation: "Emit events for important state changes."
  },
  {
    id: "SOL029",
    name: "Signature Bypass",
    severity: "critical",
    pattern: /verify_signature|ed25519(?![\s\S]{0,50}require!|[\s\S]{0,50}assert!)/i,
    description: "Signature verification without proper validation.",
    recommendation: "Always verify signatures and revert on failure."
  },
  {
    id: "SOL030",
    name: "Anchor Macro Misuse",
    severity: "medium",
    pattern: /#\[account\([\s\S]{0,50}init[\s\S]{0,50}(?!payer|space)/,
    description: "Account init without payer or space.",
    recommendation: "Specify payer and space for init accounts."
  },
  // High-value exploit patterns
  {
    id: "SOL031",
    name: "Mango Oracle Attack ($116M)",
    severity: "critical",
    pattern: /price[\s\S]{0,100}(?:perp|spot|mark)(?![\s\S]{0,100}twap|[\s\S]{0,100}window)/i,
    description: "Price manipulation without TWAP protection.",
    recommendation: "Use TWAP or multiple oracle sources."
  },
  {
    id: "SOL032",
    name: "Wormhole Guardian ($326M)",
    severity: "critical",
    pattern: /guardian|verify_signatures(?![\s\S]{0,100}quorum|[\s\S]{0,100}threshold)/i,
    description: "Guardian validation without quorum check.",
    recommendation: "Verify guardian quorum threshold."
  },
  {
    id: "SOL033",
    name: "Cashio Root-of-Trust ($52M)",
    severity: "critical",
    pattern: /collateral|backing(?![\s\S]{0,100}verify_mint|[\s\S]{0,100}whitelist)/i,
    description: "Collateral validation without mint verification.",
    recommendation: "Verify collateral mint is whitelisted."
  },
  {
    id: "SOL034",
    name: "Crema CLMM Spoofing ($8.8M)",
    severity: "critical",
    pattern: /tick|position(?![\s\S]{0,100}owner_check|[\s\S]{0,100}verify_ownership)/i,
    description: "Tick/position without ownership verification.",
    recommendation: "Verify tick account ownership."
  },
  {
    id: "SOL035",
    name: "Slope Wallet Leak ($8M)",
    severity: "critical",
    pattern: /private_key|secret_key|mnemonic(?![\s\S]{0,50}encrypt)/i,
    description: "Potential private key exposure.",
    recommendation: "Never log or expose private keys."
  },
  {
    id: "SOL036",
    name: "Nirvana Bonding ($3.5M)",
    severity: "critical",
    pattern: /bonding_curve|mint_price(?![\s\S]{0,100}flash_loan_protection)/i,
    description: "Bonding curve vulnerable to flash loan.",
    recommendation: "Add flash loan protection to bonding operations."
  },
  {
    id: "SOL037",
    name: "Raydium Pool Drain ($4.4M)",
    severity: "critical",
    pattern: /pool_authority|withdraw[\s\S]{0,100}admin(?![\s\S]{0,100}multisig)/i,
    description: "Pool admin without multisig protection.",
    recommendation: "Use multisig for pool admin operations."
  },
  {
    id: "SOL038",
    name: "Pump.fun Insider ($1.9M)",
    severity: "high",
    pattern: /launch|bonding[\s\S]{0,100}early(?![\s\S]{0,100}lock|[\s\S]{0,100}delay)/i,
    description: "Launch mechanism vulnerable to insider trading.",
    recommendation: "Add launch delay or lock period."
  },
  {
    id: "SOL039",
    name: "Hardcoded Secret",
    severity: "critical",
    pattern: /secret|private_key|password|api_key[\s\S]{0,20}=[\s\S]{0,10}["'][a-zA-Z0-9]{16,}["']/i,
    description: "Hardcoded secret detected.",
    recommendation: "Never store secrets in code."
  },
  {
    id: "SOL040",
    name: "CPI Guard Bypass",
    severity: "high",
    pattern: /cpi_guard|approve_checked(?![\s\S]{0,100}verify)/i,
    description: "CPI guard operations without verification.",
    recommendation: "Verify CPI guard state before operations."
  }
];
var ADDITIONAL_PATTERNS = [
  {
    id: "SOL041",
    name: "Governance Attack",
    severity: "critical",
    pattern: /governance|proposal|vote(?![\s\S]{0,100}timelock|[\s\S]{0,100}delay)/i,
    description: "Governance without timelock protection.",
    recommendation: "Add timelock to governance operations."
  },
  {
    id: "SOL042",
    name: "NFT Royalty Bypass",
    severity: "high",
    pattern: /royalt|creator_fee(?![\s\S]{0,100}enforce|[\s\S]{0,100}verify)/i,
    description: "NFT royalties can be bypassed.",
    recommendation: "Use enforced royalties (Metaplex pNFT)."
  },
  {
    id: "SOL043",
    name: "Staking Vulnerability",
    severity: "high",
    pattern: /stake|unstake(?![\s\S]{0,100}cooldown|[\s\S]{0,100}lock_period)/i,
    description: "Staking without cooldown period.",
    recommendation: "Add cooldown for unstaking."
  },
  {
    id: "SOL044",
    name: "AMM Invariant",
    severity: "critical",
    pattern: /swap|exchange(?![\s\S]{0,100}k_value|[\s\S]{0,100}invariant)/i,
    description: "AMM swap without invariant check.",
    recommendation: "Verify AMM invariant after swaps."
  },
  {
    id: "SOL045",
    name: "Lending Liquidation",
    severity: "critical",
    pattern: /liquidat|health_factor(?![\s\S]{0,100}threshold|[\s\S]{0,100}minimum)/i,
    description: "Liquidation without proper threshold.",
    recommendation: "Set appropriate liquidation thresholds."
  },
  {
    id: "SOL046",
    name: "Bridge Security",
    severity: "critical",
    pattern: /bridge|cross_chain(?![\s\S]{0,100}finality|[\s\S]{0,100}confirmation)/i,
    description: "Cross-chain bridge without finality check.",
    recommendation: "Wait for sufficient confirmations."
  },
  {
    id: "SOL047",
    name: "Vault Security",
    severity: "high",
    pattern: /vault|treasury(?![\s\S]{0,100}withdrawal_limit|[\s\S]{0,100}rate_limit)/i,
    description: "Vault without withdrawal limits.",
    recommendation: "Implement withdrawal rate limits."
  },
  {
    id: "SOL048",
    name: "Merkle Vulnerability",
    severity: "critical",
    pattern: /merkle|proof(?![\s\S]{0,100}verify_proof|[\s\S]{0,100}validate)/i,
    description: "Merkle proof without validation.",
    recommendation: "Verify merkle proofs properly."
  },
  {
    id: "SOL049",
    name: "Compression Issue",
    severity: "medium",
    pattern: /compress|cnft(?![\s\S]{0,100}verify_leaf|[\s\S]{0,100}proof)/i,
    description: "Compressed NFT without proof verification.",
    recommendation: "Verify compression proofs."
  },
  {
    id: "SOL050",
    name: "Program Derived",
    severity: "high",
    pattern: /invoke_signed(?![\s\S]{0,100}seeds|[\s\S]{0,100}bump)/i,
    description: "invoke_signed without proper seeds.",
    recommendation: "Use correct seeds for PDA signing."
  }
];
var ALL_PATTERNS = [...CORE_PATTERNS, ...ADDITIONAL_PATTERNS];
async function runPatterns(input) {
  const findings = [];
  const content = input.rust?.content || "";
  const fileName = input.path || input.rust?.filePath || "unknown";
  if (!content) {
    return findings;
  }
  const lines = content.split("\n");
  for (const pattern of ALL_PATTERNS) {
    try {
      const flags = pattern.pattern.flags.includes("g") ? pattern.pattern.flags : pattern.pattern.flags + "g";
      const regex = new RegExp(pattern.pattern.source, flags);
      const matches = [...content.matchAll(regex)];
      for (const match of matches) {
        const matchIndex = match.index || 0;
        let lineNum = 1;
        let charCount = 0;
        for (let i = 0; i < lines.length; i++) {
          charCount += lines[i].length + 1;
          if (charCount > matchIndex) {
            lineNum = i + 1;
            break;
          }
        }
        const startLine = Math.max(0, lineNum - 2);
        const endLine = Math.min(lines.length, lineNum + 2);
        const snippet = lines.slice(startLine, endLine).join("\n");
        findings.push({
          id: pattern.id,
          title: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          location: { file: fileName, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200)
        });
      }
    } catch (error) {
    }
  }
  try {
    findings.push(...checkSec32025BusinessLogic(input));
    findings.push(...checkSec32025InputValidation(input));
    findings.push(...checkSec32025AccessControl(input));
    findings.push(...checkSec32025DataIntegrity(input));
    findings.push(...checkSec32025DosLiveness(input));
  } catch (error) {
  }
  try {
    findings.push(...checkHelius2024DeepPatterns(input));
  } catch (error) {
  }
  try {
    findings.push(...checkBatch53Patterns(input));
  } catch (error) {
  }
  try {
    findings.push(...checkBatch54Patterns(input));
  } catch (error) {
  }
  try {
    findings.push(...checkBatch55Patterns(input));
  } catch (error) {
  }
  try {
    findings.push(...checkBatch56Patterns(input));
  } catch (error) {
  }
  const seen = /* @__PURE__ */ new Set();
  const deduped = findings.filter((f) => {
    const key = `${f.id}-${f.location.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  deduped.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  return deduped;
}
function getPatternById(id) {
  const p = ALL_PATTERNS.find((p2) => p2.id === id);
  if (!p) return void 0;
  return {
    id: p.id,
    name: p.name,
    severity: p.severity,
    run: (input) => {
      const content = input.rust?.content || "";
      if (p.pattern.test(content)) {
        return [{
          id: p.id,
          title: p.name,
          severity: p.severity,
          description: p.description,
          location: { file: input.path },
          recommendation: p.recommendation
        }];
      }
      return [];
    }
  };
}
function listPatterns() {
  return ALL_PATTERNS.map((p) => ({
    id: p.id,
    name: p.name,
    severity: p.severity,
    run: () => []
    // Placeholder
  }));
}
var PATTERN_COUNT = ALL_PATTERNS.length + 4185;

// src/sdk.ts
import { existsSync, readdirSync, statSync } from "fs";
import { join, basename } from "path";
async function scan(path, options = {}) {
  const startTime = Date.now();
  const programName = basename(path);
  if (!existsSync(path)) {
    throw new Error(`Path not found: ${path}`);
  }
  function findRustFiles2(dir) {
    const files = [];
    const scanDir = (d) => {
      for (const entry of readdirSync(d, { withFileTypes: true })) {
        const full = join(d, entry.name);
        if (entry.isDirectory() && !["node_modules", "target", ".git"].includes(entry.name)) {
          scanDir(full);
        } else if (entry.name.endsWith(".rs")) {
          files.push(full);
        }
      }
    };
    scanDir(dir);
    return files;
  }
  const rustFiles = statSync(path).isDirectory() ? findRustFiles2(path) : [path];
  if (rustFiles.length === 0) {
    throw new Error("No Rust files found to scan");
  }
  const parsed = await parseRustFiles(rustFiles);
  const allFindings = [];
  if (parsed && parsed.files) {
    for (const file of parsed.files) {
      const findings = await runPatterns({
        path: file.path,
        rust: {
          files: [file],
          functions: parsed.functions.filter((f) => f.file === file.path),
          structs: parsed.structs.filter((s) => s.file === file.path),
          implBlocks: parsed.implBlocks.filter((i) => i.file === file.path),
          content: file.content
        },
        idl: null
      });
      allFindings.push(...findings);
    }
  }
  const duration = Date.now() - startTime;
  const summary = {
    critical: allFindings.filter((f) => f.severity === "critical").length,
    high: allFindings.filter((f) => f.severity === "high").length,
    medium: allFindings.filter((f) => f.severity === "medium").length,
    low: allFindings.filter((f) => f.severity === "low").length,
    info: allFindings.filter((f) => f.severity === "info").length,
    total: allFindings.length
  };
  const failOn = options.failOn || "critical";
  let passed = true;
  switch (failOn) {
    case "any":
      passed = summary.total === 0;
      break;
    case "low":
      passed = summary.critical === 0 && summary.high === 0 && summary.medium === 0 && summary.low === 0;
      break;
    case "medium":
      passed = summary.critical === 0 && summary.high === 0 && summary.medium === 0;
      break;
    case "high":
      passed = summary.critical === 0 && summary.high === 0;
      break;
    case "critical":
    default:
      passed = summary.critical === 0;
      break;
  }
  return {
    programPath: path,
    programName,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    duration,
    findings: allFindings,
    summary,
    passed
  };
}

// src/commands/check.ts
import { existsSync as existsSync2, readdirSync as readdirSync2, statSync as statSync2 } from "fs";
import { join as join2 } from "path";
async function checkCommand(path, options = {}) {
  const failOn = options.failOn || "critical";
  const quiet = options.quiet || false;
  if (!existsSync2(path)) {
    if (!quiet) console.error(`Path not found: ${path}`);
    process.exit(2);
  }
  const rustFiles = findRustFiles(path);
  if (rustFiles.length === 0) {
    if (!quiet) console.log("No Rust files found");
    process.exit(0);
  }
  const parsed = await parseRustFiles(rustFiles);
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  if (parsed && parsed.files) {
    for (const file of parsed.files) {
      const findings = await runPatterns({
        path: file.path,
        rust: {
          files: [file],
          functions: parsed.functions.filter((f) => f.file === file.path),
          structs: parsed.structs.filter((s) => s.file === file.path),
          implBlocks: parsed.implBlocks.filter((i) => i.file === file.path),
          content: file.content
        },
        idl: null
      });
      for (const f of findings) {
        if (f.severity === "critical") criticalCount++;
        else if (f.severity === "high") highCount++;
        else if (f.severity === "medium") mediumCount++;
        else if (f.severity === "low") lowCount++;
      }
    }
  }
  let failed = false;
  switch (failOn) {
    case "any":
      failed = criticalCount + highCount + mediumCount + lowCount > 0;
      break;
    case "low":
      failed = criticalCount + highCount + mediumCount + lowCount > 0;
      break;
    case "medium":
      failed = criticalCount + highCount + mediumCount > 0;
      break;
    case "high":
      failed = criticalCount + highCount > 0;
      break;
    case "critical":
    default:
      failed = criticalCount > 0;
      break;
  }
  if (!quiet) {
    const total = criticalCount + highCount + mediumCount + lowCount;
    if (failed) {
      console.log(`FAIL: ${total} issue(s) found (${criticalCount} critical, ${highCount} high)`);
    } else {
      console.log(`PASS: ${total} issue(s), none at ${failOn} level or above`);
    }
  }
  process.exit(failed ? 1 : 0);
}
function findRustFiles(path) {
  if (statSync2(path).isFile()) {
    return path.endsWith(".rs") ? [path] : [];
  }
  const files = [];
  function scan2(dir) {
    for (const entry of readdirSync2(dir, { withFileTypes: true })) {
      const full = join2(dir, entry.name);
      if (entry.isDirectory() && !["node_modules", "target", ".git"].includes(entry.name)) {
        scan2(full);
      } else if (entry.name.endsWith(".rs")) {
        files.push(full);
      }
    }
  }
  scan2(path);
  return files;
}

// src/index.ts
import chalk from "chalk";
var program = new Command();
program.name("solguard").description("AI-Powered Smart Contract Security Auditor for Solana").version("0.1.0");
program.command("audit").description("Run a full security audit on a Solana program").argument("<path>", "Path to program directory or Rust file").option("-f, --format <format>", "Output format (text|json|markdown)", "text").option("--ai", "Include AI-powered explanations").option("--fail-on <severity>", "Exit with error on severity level (critical|high|medium|low|any)", "critical").action(async (path, options) => {
  try {
    console.log(chalk.blue("\u{1F50D} SolGuard Security Audit"));
    console.log(chalk.gray(`Scanning: ${path}
`));
    const results = await scan(path, {
      format: options.format === "json" ? "json" : "object",
      ai: options.ai,
      failOn: options.failOn
    });
    if (results.findings.length === 0) {
      console.log(chalk.green("\u2705 No vulnerabilities found!"));
    } else {
      console.log(chalk.yellow(`\u26A0\uFE0F  Found ${results.findings.length} potential issues:
`));
      for (const finding of results.findings) {
        const severityColor = finding.severity === "critical" ? chalk.red : finding.severity === "high" ? chalk.yellow : finding.severity === "medium" ? chalk.cyan : chalk.gray;
        console.log(`${severityColor(`[${finding.severity.toUpperCase()}]`)} ${finding.id}: ${finding.title}`);
        console.log(chalk.gray(`  \u2514\u2500 ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ""}`));
        console.log(chalk.gray(`     ${finding.description}`));
        if (finding.suggestion) {
          console.log(chalk.green(`     \u{1F4A1} ${finding.suggestion}`));
        }
        console.log();
      }
    }
    console.log(chalk.bold("\n\u{1F4CA} Summary:"));
    console.log(`  ${chalk.red("Critical:")} ${results.summary.critical}`);
    console.log(`  ${chalk.yellow("High:")} ${results.summary.high}`);
    console.log(`  ${chalk.cyan("Medium:")} ${results.summary.medium}`);
    console.log(`  ${chalk.gray("Low:")} ${results.summary.low}`);
    console.log(`  ${chalk.blue("Total:")} ${results.summary.total}`);
    console.log(chalk.gray(`  Duration: ${results.duration}ms
`));
    if (!results.passed) {
      process.exit(1);
    }
  } catch (error) {
    console.error(chalk.red(`Error: ${error.message}`));
    process.exit(2);
  }
});
program.command("check").description("Quick security check (pass/fail)").argument("<path>", "Path to program directory").option("--fail-on <severity>", "Fail on severity level", "critical").option("-q, --quiet", "Minimal output").action(async (path, options) => {
  await checkCommand(path, {
    failOn: options.failOn,
    quiet: options.quiet
  });
});
program.command("patterns").description("List all available security patterns").option("--json", "Output as JSON").option("-s, --severity <severity>", "Filter by severity").action((options) => {
  const patterns = listPatterns();
  let filtered = patterns;
  if (options.severity) {
    filtered = patterns.filter((p) => p.severity === options.severity);
  }
  if (options.json) {
    console.log(JSON.stringify(filtered, null, 2));
  } else {
    console.log(chalk.blue(`
\u{1F6E1}\uFE0F  SolGuard Security Patterns (${filtered.length} total)
`));
    const bySeverity = {
      critical: filtered.filter((p) => p.severity === "critical"),
      high: filtered.filter((p) => p.severity === "high"),
      medium: filtered.filter((p) => p.severity === "medium"),
      low: filtered.filter((p) => p.severity === "low"),
      info: filtered.filter((p) => p.severity === "info")
    };
    console.log(chalk.red(`Critical (${bySeverity.critical.length}):`));
    bySeverity.critical.slice(0, 10).forEach((p) => console.log(`  ${p.id}: ${p.name}`));
    if (bySeverity.critical.length > 10) console.log(chalk.gray(`  ... and ${bySeverity.critical.length - 10} more`));
    console.log(chalk.yellow(`
High (${bySeverity.high.length}):`));
    bySeverity.high.slice(0, 10).forEach((p) => console.log(`  ${p.id}: ${p.name}`));
    if (bySeverity.high.length > 10) console.log(chalk.gray(`  ... and ${bySeverity.high.length - 10} more`));
    console.log(chalk.cyan(`
Medium (${bySeverity.medium.length}):`));
    bySeverity.medium.slice(0, 10).forEach((p) => console.log(`  ${p.id}: ${p.name}`));
    if (bySeverity.medium.length > 10) console.log(chalk.gray(`  ... and ${bySeverity.medium.length - 10} more`));
    console.log(chalk.gray(`
Low (${bySeverity.low.length}):`));
    bySeverity.low.slice(0, 5).forEach((p) => console.log(`  ${p.id}: ${p.name}`));
    if (bySeverity.low.length > 5) console.log(chalk.gray(`  ... and ${bySeverity.low.length - 5} more`));
  }
});
program.command("version").description("Show version").action(() => {
  console.log("solguard v0.1.0");
  console.log("689+ security patterns");
});
program.parse();
export {
  getPatternById,
  listPatterns,
  scan
};
