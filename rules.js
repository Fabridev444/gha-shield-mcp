// gha-shield free-tier rules. Pure ESM, no build step.
// Each rule: `(workflow) => Finding[]`. Workflow is a parsed YAML object.
//
// Finding shape:
//   { id, severity: "crit"|"high"|"med"|"low"|"info", title, description, location, fix }

import { parse } from "yaml";

const FREE_RULES = [
  rule1UnpinnedActions,
  rule2PRTargetCheckout,
  rule3CommandInjection,
  rule4MissingPermissions,
  rule5ContinueOnErrorAuth,
  rule6SecretsInIf,
  rule7CurlPipeBash,
  rule8UntrustedDownload,
  rule9ScheduledBroadPerms,
  rule10WorkflowRunUntrusted,
  rule11HardcodedSecret,
  rule12ThirdPartyActionWithSecret,
  rule13NoTimeout,
];

// Trust list — actions whose owners are vetted enough that handing them a token
// is acceptable. Everything outside this list and outside "./local-action" gets
// flagged when the workflow hands it a credential. Add cautiously — these are
// owners whose actions are widely used and whose track record on security is
// documented in `docs/trusted-owners.md`.
const TRUSTED_ACTION_OWNERS = new Set([
  "actions", "github", "docker",
  "aws-actions", "google-github-actions", "azure",
  "peter-evans", "oven-sh", "astral-sh",
  "step-security", "cloudflare", "vercel", "hashicorp", "pulumi",
  "sigstore", "slsa-framework",
]);

export function runFreeRules(text) {
  if (!text || typeof text !== "string" || !text.trim()) {
    return [emptyFinding("No YAML content. Paste a workflow file above.")];
  }
  let workflow;
  try {
    workflow = parse(text);
  } catch (e) {
    return [{
      id: "parse-error",
      severity: "high",
      title: "YAML parse error",
      description: e.message,
      location: "",
      fix: "Fix the YAML syntax. GitHub Actions itself will refuse to load an unparseable workflow.",
    }];
  }
  return runFreeRulesParsed(workflow);
}

// Pure-logic entry point — no YAML parsing. Used by unit tests and any caller
// that already has a parsed workflow AST.
export function runFreeRulesParsed(workflow) {
  if (!workflow || typeof workflow !== "object") {
    return [emptyFinding("Parsed YAML is empty or scalar — expected a workflow object.")];
  }
  return FREE_RULES.flatMap((r) => safe(r, workflow));
}

function safe(fn, w) {
  try {
    return fn(w) ?? [];
  } catch (e) {
    return [{
      id: "rule-error",
      severity: "info",
      title: `Rule "${fn.name}" failed`,
      description: e.message,
      location: "",
      fix: "Open an issue with a YAML repro and we'll patch the rule.",
    }];
  }
}

function emptyFinding(msg) {
  return { id: "empty", severity: "info", title: "Nothing to scan", description: msg, location: "", fix: "" };
}

// ---------- Helpers ----------

function eachStep(workflow, cb) {
  const jobs = workflow.jobs ?? {};
  for (const [jobName, job] of Object.entries(jobs)) {
    if (!job || typeof job !== "object") continue;
    const steps = job.steps ?? [];
    for (let i = 0; i < steps.length; i++) cb(steps[i], { jobName, stepIndex: i });
  }
}

function normalizeTriggers(on) {
  if (!on) return [];
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return on.map(String);
  if (typeof on === "object") return Object.keys(on);
  return [];
}

// ---------- Rule 1: Unpinned third-party actions ----------

function rule1UnpinnedActions(w) {
  const findings = [];
  eachStep(w, (step, ctx) => {
    if (typeof step?.uses !== "string") return;
    const [actionPath, ref] = step.uses.split("@");
    if (!ref) return;
    if (actionPath.startsWith("./") || actionPath.startsWith("docker://")) return;
    if (/^[a-f0-9]{40}$/i.test(ref)) return; // already a SHA
    findings.push({
      id: "unpinned-action",
      severity: "high",
      title: "Third-party action not pinned to a commit SHA",
      description: `\`${step.uses}\` is pinned to a tag or branch (\`${ref}\`). A malicious tag-move or force-push can swap the code in your CI without notice. Even GitHub's own \`actions/*\` repos can be compromised — pinning to SHA is the only mitigation.`,
      location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].uses`,
      fix: `Replace with the full 40-char commit SHA, leave the tag as a comment for legibility:\n  uses: ${actionPath}@<40-char-sha>  # ${ref}`,
    });
  });
  return findings;
}

// ---------- Rule 2: pull_request_target + checkout of PR-controlled ref ----------

function rule2PRTargetCheckout(w) {
  const triggers = normalizeTriggers(w.on);
  if (!triggers.includes("pull_request_target")) return [];
  const findings = [];
  eachStep(w, (step, ctx) => {
    if (typeof step?.uses !== "string") return;
    if (!step.uses.startsWith("actions/checkout@")) return;
    const refValue = step.with?.ref;
    if (refValue == null) return;
    const refStr = String(refValue);
    if (/(pull_request|head|sha|ref|pr)/i.test(refStr)) {
      findings.push({
        id: "prtarget-checkout-prref",
        severity: "crit",
        title: "pull_request_target combined with checkout of PR-controlled ref",
        description: `Workflow is triggered by \`pull_request_target\` AND checks out attacker-controlled code via \`ref: ${refStr}\`. PR code now runs with the base repo's secrets and write token — a well-known privilege escalation pattern (see the \`actions/checkout\` security advisory).`,
        location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].with.ref`,
        fix: "Either: change the trigger to `pull_request` (which doesn't expose secrets to forks), OR remove the `ref:` so checkout uses the base branch and skips the PR code entirely.",
      });
    }
  });
  return findings;
}

// ---------- Rule 3: Command injection via untrusted ${{ ... }} in run blocks ----------

// Fields under github.event.{pull_request,issue,comment,review,workflow_run}.<X>
// that are integers, booleans, ISO dates or other always-safe scalars. These get
// substituted as numbers/strings of constrained shape and cannot inject shell.
const SAFE_LEAF_FIELDS = new Set([
  "number", "id", "node_id", "comments",
  "created_at", "updated_at", "closed_at", "merged_at", "submitted_at",
  "locked", "draft", "merged", "rebaseable", "mergeable", "mergeable_state",
  "additions", "deletions", "changed_files", "commits", "review_comments",
  "state", "active_lock_reason",
]);

function isTaintedRunExpr(text) {
  // Matches `${{ github.event.<scope>.<rest> }}` or `${{ inputs.<name> }}` or
  // `${{ github.head_ref }}` / `${{ github.ref }}`. Returns the matched substring,
  // or null if all matches in the text resolve to a SAFE_LEAF_FIELDS terminal.
  const EXPR = /\$\{\{\s*(github\.event\.(pull_request|issue|comment|head_commit|review|workflow_run)\.([\w.]+)|github\.head_ref|github\.ref|inputs\.([\w.]+))[^}]*\}\}/g;
  let m;
  while ((m = EXPR.exec(text)) !== null) {
    const path = m[3]; // event leaf path
    if (path) {
      // Take the LAST segment of the chain — the leaf scalar.
      const leaf = path.split(".").pop();
      if (SAFE_LEAF_FIELDS.has(leaf)) continue;
      return m[0];
    }
    // Non-event expressions (head_ref, ref, inputs.*) are always tainted.
    return m[0];
  }
  return null;
}

function rule3CommandInjection(w) {
  const findings = [];
  eachStep(w, (step, ctx) => {
    if (typeof step?.run !== "string") return;
    const hit = isTaintedRunExpr(step.run);
    if (!hit) return;
    findings.push({
      id: "cmd-injection",
      severity: "crit",
      title: "Untrusted GitHub context expanded into shell `run:` block",
      description: `\`${hit}\` is interpolated directly into a shell command. Anything an attacker can shape (PR title, branch name, comment body) becomes part of the script — a classic command injection sink.`,
      location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].run`,
      fix: "Pass the value through `env` then reference the env var in the script:\n  env:\n    PR_TITLE: ${{ github.event.pull_request.title }}\n  run: echo \"$PR_TITLE\"",
    });
  });
  return findings;
}

// ---------- Rule 4: Missing permissions block ----------

function rule4MissingPermissions(w) {
  const triggers = normalizeTriggers(w.on);
  const externalTriggers = ["push", "pull_request", "pull_request_target", "issues", "issue_comment", "release", "schedule", "workflow_run"];
  const external = triggers.some((t) => externalTriggers.includes(t));
  if (!external) return [];
  if (w.permissions !== undefined) return [];
  const jobs = w.jobs ?? {};
  const jobNames = Object.keys(jobs);
  if (jobNames.length === 0) return [];
  const missing = jobNames.filter((name) => jobs[name]?.permissions === undefined);
  if (missing.length === 0) return [];
  return [{
    id: "no-permissions",
    severity: "med",
    title: "No `permissions:` block — GITHUB_TOKEN defaults to broad scope",
    description: `Jobs without an explicit \`permissions:\` block (${missing.join(", ")}) inherit the org/repo default token scopes — usually broader than they need. Any compromised step gets the full default permissions to read/write the repo.`,
    location: missing.length === jobNames.length ? "(workflow root)" : `jobs.{${missing.join(",")}}`,
    fix: "Add `permissions: read-all` at the workflow root (or `permissions: { contents: read }` for stricter), then override per-job only where you need write/issues/packages.",
  }];
}

// ---------- Rule 5: continue-on-error true on auth/test step ----------

function rule5ContinueOnErrorAuth(w) {
  const findings = [];
  const SUSPECT = /(auth|login|signin|verify|test|check|lint|audit|security|scan|coverage|typecheck|tsc)/i;
  eachStep(w, (step, ctx) => {
    if (step?.["continue-on-error"] !== true) return;
    const haystack = `${step?.name ?? ""} ${step?.run ?? ""} ${step?.uses ?? ""}`;
    if (!SUSPECT.test(haystack)) return;
    const label = step.name ?? step.uses ?? (step.run ? step.run.slice(0, 40) + "…" : "step");
    findings.push({
      id: "continue-on-error-auth",
      severity: "high",
      title: "`continue-on-error: true` on a security/test step",
      description: `Step "${label}" silences failures. If this is an auth/test/lint/audit step, real failures slip through the pipeline undetected — your CI shows green while the check failed.`,
      location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}]`,
      fix: "Remove `continue-on-error: true`. If you need to keep going on partial failure, wrap the step in a script that explicitly fails the job on the conditions you care about.",
    });
  });
  return findings;
}

// ---------- Rule 7: curl | bash or wget | sh patterns ----------

function rule7CurlPipeBash(w) {
  const findings = [];
  // curl ... | bash | sh | zsh | python  (any combination of flags between curl and pipe)
  const PATTERN = /\b(curl|wget|fetch)\s+[^|]*\|\s*(bash|sh|zsh|python3?|node|ruby|perl)\b/i;
  eachStep(w, (step, ctx) => {
    if (typeof step?.run !== "string") return;
    const m = step.run.match(PATTERN);
    if (!m) return;
    findings.push({
      id: "curl-pipe-bash",
      severity: "high",
      title: "Untrusted remote script piped directly into a shell",
      description: `Step pipes the output of \`${m[1]}\` straight into \`${m[2]}\`. The remote endpoint controls what executes on your runner — a single compromise of the URL (DNS hijack, CDN poisoning, repo takeover) is a remote code execution.`,
      location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].run`,
      fix: "Download to a file first, verify checksum, then run:\n  - curl -fsSLO https://… && echo \"<expected-sha256>  file\" | sha256sum -c && bash file",
    });
  });
  return findings;
}

// ---------- Rule 8: download from untrusted host without checksum ----------

function rule8UntrustedDownload(w) {
  const findings = [];
  // Match curl/wget to gist/raw.github/pastebin without a checksum check on the same step
  const DL = /(curl|wget)\s+[^|;]*?(https?:\/\/(?:gist\.githubusercontent\.com|raw\.githubusercontent\.com|pastebin\.com|paste\.ee|0bin\.net|transfer\.sh)[^\s'"`]*)/i;
  const CHECKSUM = /(sha256sum|shasum|openssl\s+dgst|sha1sum|md5sum)/i;
  eachStep(w, (step, ctx) => {
    if (typeof step?.run !== "string") return;
    const m = step.run.match(DL);
    if (!m) return;
    if (CHECKSUM.test(step.run)) return; // user is verifying — skip
    findings.push({
      id: "untrusted-download",
      severity: "med",
      title: "Download from gist/raw/paste host without checksum verification",
      description: `Step fetches \`${m[2]}\` and no checksum command (sha256sum/shasum/openssl dgst) appears in the same step. Anyone with write access to the source can swap the file silently.`,
      location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].run`,
      fix: "Pin the URL to a commit (raw.githubusercontent.com/owner/repo/<sha>/path) AND verify checksum after download.",
    });
  });
  return findings;
}

// ---------- Rule 9: scheduled workflow with broad/missing permissions ----------

function rule9ScheduledBroadPerms(w) {
  const triggers = normalizeTriggers(w.on);
  if (!triggers.includes("schedule")) return [];
  // If permissions block exists and is "read-all" or tighter, OK.
  const perm = w.permissions;
  const isTight = (p) => {
    if (p === undefined) return false;
    if (typeof p === "string") return p === "read-all" || p === "none";
    if (typeof p === "object") {
      // any value of `write` or `write-all` is broad
      return !Object.values(p).some((v) => /write/i.test(String(v)));
    }
    return false;
  };
  if (isTight(perm)) return [];
  // Check per-job permissions
  const jobs = w.jobs ?? {};
  const broadJobs = Object.entries(jobs)
    .filter(([_, job]) => !isTight(job?.permissions))
    .map(([name]) => name);
  if (broadJobs.length === 0) return [];
  return [{
    id: "scheduled-broad-perms",
    severity: "med",
    title: "`schedule:` workflow without tight `permissions:`",
    description: `Scheduled workflows run with the repo's default token and no PR review gate. Job(s) ${broadJobs.join(", ")} have no explicit read-only \`permissions:\`. A compromised dependency in a scheduled run can push commits or open PRs.`,
    location: broadJobs.length === Object.keys(jobs).length ? "(workflow root)" : `jobs.{${broadJobs.join(",")}}`,
    fix: "Add at the workflow root:\n  permissions: read-all\n…then override per-job only where you need write.",
  }];
}

// ---------- Rule 10: workflow_run trigger with checkout from sibling workflow's ref ----------

function rule10WorkflowRunUntrusted(w) {
  const triggers = normalizeTriggers(w.on);
  if (!triggers.includes("workflow_run")) return [];
  const findings = [];
  eachStep(w, (step, ctx) => {
    if (typeof step?.uses !== "string") return;
    if (!step.uses.startsWith("actions/checkout@")) return;
    const refValue = step.with?.ref;
    if (refValue == null) return;
    const refStr = String(refValue);
    if (/workflow_run|head_sha|pull_requests/i.test(refStr)) {
      findings.push({
        id: "workflow-run-untrusted-checkout",
        severity: "crit",
        title: "workflow_run trigger checks out code from triggering workflow",
        description: `\`workflow_run\` fires after another workflow (often a PR-triggered one) completes. Checking out \`${refStr}\` brings the triggering workflow's code into a context that has access to repository secrets — the same privilege-escalation class as \`pull_request_target\` + checkout.`,
        location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].with.ref`,
        fix: "Restrict to base branch and only consume the data (artifacts, PR number) the trigger emits — never execute the triggering workflow's code.",
      });
    }
  });
  return findings;
}

// ---------- Rule 11: hardcoded credential in env value ----------

function rule11HardcodedSecret(w) {
  const findings = [];
  // Env keys that signal a secret. Conservative — high-precision over high-recall.
  const SECRET_KEY = /(secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|private[_-]?key|jwt|bearer|sk[_-]live|sk[_-]test|rk[_-]live|rk[_-]test|pat[_-]|ghp[_-]|github[_-]?token|openai|anthropic|stripe)/i;
  // Common high-confidence secret value shapes (provider-specific prefixes).
  const KNOWN_PREFIXES = /^(sk-[A-Za-z0-9]{16,}|sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|rk_test_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{16,}|gho_[A-Za-z0-9]{16,}|ghs_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|xox[abps]-[A-Za-z0-9-]{16,}|AIza[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16})$/;
  // Long opaque-looking strings inside secret-named keys.
  const LONG_OPAQUE = /^[A-Za-z0-9+/=_\-]{24,}$/;
  // Safe references (skip these).
  const SAFE_REF = /^\s*\$\{\{\s*(secrets|vars|env|inputs|github|steps|matrix|needs|job|runner)\./;

  function inspectEnv(obj, path) {
    const env = obj?.env;
    if (!env || typeof env !== "object") return;
    for (const [k, raw] of Object.entries(env)) {
      if (raw == null) continue;
      const v = String(raw);
      if (!v.trim()) continue;
      if (SAFE_REF.test(v)) continue;
      // Known credential shapes ALWAYS flag, even if key name is benign.
      if (KNOWN_PREFIXES.test(v.trim())) {
        findings.push({
          id: "hardcoded-secret",
          severity: "crit",
          title: `Hard-coded secret in env (${k})`,
          description: `\`${k}\` is set to what looks like a real provider key (matches known prefix pattern). The value is committed to the repo and will appear in any fork, mirror, or git blame forever.`,
          location: `${path}.env.${k}`,
          fix: `Move the value to a repo or environment secret and reference it:\n  env:\n    ${k}: \${{ secrets.${k.toUpperCase().replace(/[^A-Z0-9_]/g, "_")} }}\nThen ROTATE the leaked key immediately — git history retains it.`,
        });
        continue;
      }
      // Key name suggests secret + long opaque value (high-precision heuristic).
      if (SECRET_KEY.test(k) && LONG_OPAQUE.test(v.trim())) {
        findings.push({
          id: "hardcoded-secret",
          severity: "crit",
          title: `Hard-coded secret in env (${k})`,
          description: `\`${k}\` has a long opaque value but its name signals a credential. If this is a real secret the repo just leaked it.`,
          location: `${path}.env.${k}`,
          fix: `Move to repo secrets:\n  env:\n    ${k}: \${{ secrets.${k.toUpperCase().replace(/[^A-Z0-9_]/g, "_")} }}\nRotate the leaked key.`,
        });
      }
    }
  }

  inspectEnv(w, "(workflow)");
  const jobs = w.jobs ?? {};
  for (const [jn, job] of Object.entries(jobs)) {
    if (!job) continue;
    inspectEnv(job, `jobs.${jn}`);
    const steps = job.steps ?? [];
    for (let i = 0; i < steps.length; i++) {
      inspectEnv(steps[i], `jobs.${jn}.steps[${i}]`);
    }
  }
  return findings;
}

// ---------- Rule 12: third-party action receiving a token/secret ----------

function rule12ThirdPartyActionWithSecret(w) {
  const findings = [];
  const SECRET_REF = /\$\{\{\s*secrets\.[A-Z0-9_]+/i;
  const TOKEN_REF = /\$\{\{\s*(secrets\.GITHUB_TOKEN|github\.token)\s*\}\}/i;

  eachStep(w, (step, ctx) => {
    if (typeof step?.uses !== "string") return;
    const actionPath = step.uses.split("@")[0];
    if (actionPath.startsWith("./") || actionPath.startsWith("docker://")) return;
    const owner = actionPath.split("/")[0];
    if (TRUSTED_ACTION_OWNERS.has(owner)) return;
    const withBlock = step.with;
    if (!withBlock || typeof withBlock !== "object") return;
    // Walk every value in `with:` looking for secrets references.
    for (const [k, raw] of Object.entries(withBlock)) {
      if (raw == null) continue;
      const v = String(raw);
      if (!v) continue;
      let severity = null;
      let detail = "";
      if (TOKEN_REF.test(v)) {
        severity = "high";
        detail = "GITHUB_TOKEN";
      } else if (SECRET_REF.test(v)) {
        severity = "med";
        detail = "a secret";
      }
      if (severity) {
        findings.push({
          id: "third-party-action-token",
          severity,
          title: `Third-party action receives ${detail}`,
          description: `Step uses \`${actionPath}\` (owner \`${owner}\` is not in the trusted list) and passes ${detail} via \`with.${k}\`. The action's code can exfiltrate the value — there's no GitHub-level sandbox between an action and the credentials it's handed. The action could be backdoored today or via a future tag/SHA swap.`,
          location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].with.${k}`,
          fix: `Three options, in order of safety:\n  1. Vendor the action's logic into your own \`./.github/actions/\` and audit it.\n  2. Pin to a SHA you've reviewed (the unpinned-action rule already flags this separately).\n  3. Use the narrowest possible scoped PAT (not GITHUB_TOKEN) and rotate it.\nIf the action genuinely needs ${detail}, document why in the workflow comment so reviewers know it was a deliberate decision.`,
        });
      }
    }
  });
  return findings;
}

// ---------- Rule 13: job without `timeout-minutes` on externally-triggered workflow ----------

function rule13NoTimeout(w) {
  const triggers = normalizeTriggers(w.on);
  const externalTriggers = ["push", "pull_request", "pull_request_target", "issues", "issue_comment", "release", "schedule", "workflow_run"];
  const external = triggers.some((t) => externalTriggers.includes(t));
  if (!external) return [];
  const jobs = w.jobs ?? {};
  const missing = Object.entries(jobs)
    .filter(([_, job]) => job && typeof job === "object" && job["timeout-minutes"] === undefined && job.uses === undefined)
    .map(([name]) => name);
  if (missing.length === 0) return [];
  return [{
    id: "no-timeout-minutes",
    severity: "low",
    title: "Job has no `timeout-minutes` on an externally-triggered workflow",
    description: `Job(s) ${missing.join(", ")} have no \`timeout-minutes\`. GitHub's default is 6 hours per job — long enough that a hung or attacker-induced infinite loop burns through your Actions minutes quota and delays everyone else's CI. On self-hosted runners the default depends on runner config and may be unbounded.`,
    location: `jobs.{${missing.join(",")}}`,
    fix: "Add per-job:\n  timeout-minutes: 15   # or whatever value covers your p95 plus headroom",
  }];
}

// ---------- Rule 6: secrets.* referenced inside if: ----------

function rule6SecretsInIf(w) {
  const findings = [];
  const SECRET = /\$\{\{\s*secrets\.[A-Z0-9_]+/i;
  function visit(obj, path) {
    if (!obj || typeof obj !== "object") return;
    if (typeof obj.if === "string" && SECRET.test(obj.if)) {
      findings.push({
        id: "secret-in-if",
        severity: "med",
        title: "Secret referenced inside an `if:` expression",
        description: `\`if: ${obj.if}\` references a secret. When debug logging is enabled (\`ACTIONS_STEP_DEBUG=true\`) GitHub prints the resolved \`if\` expression — including the secret's expanded value — into the run logs.`,
        location: path,
        fix: "Move the comparison to an env var and gate on the env value instead:\n  env:\n    HAS_KEY: ${{ secrets.MY_KEY != '' }}\n  if: env.HAS_KEY == 'true'",
      });
    }
  }
  const jobs = w.jobs ?? {};
  for (const [jn, job] of Object.entries(jobs)) {
    if (!job) continue;
    visit(job, `jobs.${jn}`);
    const steps = job.steps ?? [];
    for (let i = 0; i < steps.length; i++) visit(steps[i], `jobs.${jn}.steps[${i}]`);
  }
  return findings;
}
