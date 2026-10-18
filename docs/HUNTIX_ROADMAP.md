# HUNTIX Roadmap — from scanner to evidence-driven hunter

Status: proposal, not implemented. Baseline: branch `huntix/evidence-gates`
(commit `693667a`). The Zero-Day engine (`core/zeroday.py`) is unchanged and
out of scope here.

## Design rule for everything below

Every new capability follows the same loop the evidence gates already enforce:

```
hypothesis  →  controlled experiment  →  captured evidence  →  proof gate
(lead)          (scope + escalation        (observed output /      (CONFIRMED only
                 gates, test accounts)      attested recording)     with 3 pillars)
                                                     ↓
                               FP screen → pre-validation → /handoff → validator → ywh:triage
```

No module writes findings directly. Modules emit **leads** with the
experiment that would prove them; only the proof gate confirms.

## What exists today (relevant inventory)

| Area | Exists | Where |
|---|---|---|
| Scope enforcement on every command / HttpClient hop | yes | `core/scope.py`, `core/runner.py`, `core/zeroday_active.py` |
| Human-only approval for state change / data access / load | yes | `core/escalation.py`, `ToolRunner.on_approve` |
| Proof gate, recorded-evidence attestation, controlled replay | yes | `core/proof.py`, `AgentMode.attest_evidence/reproduce_finding` |
| Offline 7-Question Gate reading `validator.md` + `ywh:gotchas` | yes | `core/validation.py` |
| FP screen + human review | yes | `core/fp_filter.py` |
| Claude Code handoff (packet → validator → ywh:write → ywh:triage) | yes | `core/handoff.py`, `HUNTIX/.claude/commands/hackbot-validate.md` |
| Intercepting proxy with request/response capture (`CapturedRequest`) | yes, single identity | `core/proxy.py` |
| Session-aware HTTP client (cookies, auth token, custom headers) | yes, one identity | `core/zeroday_active.py` `HttpClient`, `ScanConfig` |
| Plugin system (agent-callable Python tools) | yes | `core/plugins.py` |
| GraphQL | tech fingerprint only | `zeroday_active.py` (detects "graphql") |
| OpenAPI / Swagger parsing | **no** | — |
| Multiple identities / roles / tenants | **no** | — |
| Burp integration | only manual: attest Burp-exported files | `/attest` |
| MCP server | **no** (only `glm` MCP configured in Claude Code) | — |
| Claude-side methodology | `graphql-audit`, `web2-vuln-classes`, `bug-bounty`, `chain-builder`, `validator`, `report-writer` | `~/.claude/skills`, `~/.claude/agents` |
| Local tools | `nuclei httpx ffuf katana arjun graphql-cop` installed; `graphw00f clairvoyance inql mitmproxy` not installed; Burp Suite.app installed | — |

Known gaps carried over from the gates work (fix before Phase 1):

- GUI has no approval queue → every approval-gated action is refused in the GUI.
- GUI has no `/attest`, `/replay`, `/review` UI (API endpoint exists for review only).

---

## Phase 0 — Foundations (everything else depends on these)

### 0.1 Identity Vault  (enables Multi-Account Testing)

**Missing.** HackBot knows one session at a time.

**Build:** `core/identities.py`

- `Identity(name, role, tenant, auth={cookies|headers|bearer}, owned_objects=[])`
  loaded from a local file the hunter writes (e.g. `identities.yaml`, git-ignored).
- Secrets never enter AI prompts, logs, reports, packets or the RAG store:
  the agent sees `identity:user-b`, the runner substitutes credentials at
  execution time; a redaction filter runs on every captured output before
  it is stored (`<redacted:user-b.session>`).
- **Ownership ledger:** which object IDs belong to which identity (seeded by
  the hunter, extended automatically when identity X creates an object).
  This is what makes "A read B's object" provable instead of guessed.
- Only hunter-controlled test accounts. Guardrail: the vault refuses to
  load more identities than the program allows, and has no "harvest
  credentials" path at all.

**Integration:** `HttpClient` / `ToolRunner` get an `identity=` parameter;
`Finding.attacker_identity / victim_identity` (already exist) are filled from
it, so validator Q6 cross-identity checks become automatic.

### 0.2 Request Corpus

**Partly exists** (`CapturedRequest` in the proxy).

**Build:** `core/corpus.py` — one normalized store of HTTP exchanges with
`source` (hackbot-proxy | burp | har | openapi | js-routes | graphql),
`identity`, endpoint template (`/v1/orders/{id}`), parameters with inferred
types (int, uuid, email, opaque), and response fingerprint.

**Importers:** HackBot proxy (direct), HAR, Burp XML export (Phase 4), OpenAPI
3 / Swagger 2 (new), routes extracted from JS bundles (reuse `katana` output).

Everything in Phases 1–3 reads from the corpus; nothing re-crawls blindly.

### 0.3 Differential Replay Engine

**Missing.** The core primitive for authorization testing.

**Build:** `core/authz_diff.py`

- Input: a corpus exchange owned by identity B, plus a list of identities.
- Replays it as A / anonymous / other role, through `HttpClient` →
  scope gate → escalation gate. **Only GET/HEAD/OPTIONS run automatically**;
  any other method goes to the approval queue and only against objects in
  the ownership ledger.
- Compares: status, normalized body similarity (strip timestamps, CSRF
  tokens, nonces), and **owner markers** (B's email / id / name taken from
  the ledger) present in A's response.
- Output: a `DiffResult` that already contains the verbatim excerpt and step
  number, so a confirmed case flows straight into the proof gate with
  `behavior / boundary / impact / evidence_refs / identities` filled from
  facts, not AI prose.

---

## Phase 1 — Authorization testing

### 1.1 Advanced BOLA / IDOR

| | |
|---|---|
| Exists | Proof-gate + validator rules for IDOR (two identities, victim identifier in evidence, gotchas checklist); FP rules `SELF_TARGET`, `STATUS_CODE_ONLY` |
| Missing | object-ID discovery, ownership-aware substitution, differential comparison, ID-predictability classification |

**Build (`core/bola.py`, on top of 0.1–0.3):**

1. **ID discovery** from the corpus: path segments, query/body params, JSON
   fields named `*_id`, `owner`, `account`, nested objects; also IDs that
   appear in responses of one endpoint and as inputs to another (reference
   graph).
2. **Classification** per ID: sequential int, UUIDv4, hash, composite,
   encoded (base64/JWT claim). Feeds the gotchas note that non-guessable IDs
   are `AC:H` — the packet states where a victim ID would come from.
3. **Substitution plans:** for each A-request carrying an ID, swap in B's
   owned ID from the ledger (never guessed IDs of real users). Variants that
   matter in practice: path vs body vs header placement, parameter
   pollution (`id=A&id=B`), type juggling (`"123"` vs `123`, array wrap),
   alternate API versions / content types of the same resource.
4. **Leads → confirmations:** a variant becomes a lead when the differential
   engine sees a 2xx with no owner marker; it is confirmed only when B's
   marker appears in A's response (read) or B's object state changes
   (write — approval + ledger object only + before/after snapshot).

### 1.2 BFLA (function-level authorization)

| | |
|---|---|
| Exists | Nothing specific; FP rules `LOGIN_REDIRECT`, `SPA_SHELL_ONLY` already kill the classic BFLA false positives |
| Missing | role model, function inventory, role×function matrix |

**Build (`core/bfla.py`):**

1. **Function inventory:** endpoints seen only under a privileged identity in
   the corpus, admin/staff routes from OpenAPI specs and JS bundles, and
   method siblings (`GET /users/{id}` seen → probe whether `PUT/DELETE`
   exist via `OPTIONS` / documented spec — no blind destructive calls).
2. **Role matrix:** identities × functions, filled by the differential
   engine. Read functions run automatically; write/admin functions are
   queued for approval and run against ledger-owned objects only.
3. **Evidence:** privileged data or a completed privileged action visible in
   the low-privilege response (not "the page loaded"), plus the matrix row
   exported into the packet as the reproduction table.

### 1.3 Multi-Account Testing (cross-cutting)

Delivered by 0.1 + 0.3; additional work:

- Tenant boundary tests (same role, different tenant) as a separate
  boundary type in the proof gate (`boundary: tenant isolation`).
- Session lifecycle checks that are actually reportable (token still valid
  after password change / role downgrade) — only on own test accounts.
- Packet + `/hackbot-validate` gain an identities table (names, roles,
  tenants — never secrets).

---

## Phase 2 — GraphQL Intelligence

| | |
|---|---|
| Exists | GraphQL tech detection; `graphql-cop` installed; `graphql-audit` skill on the Claude side; validator never-submit already kills "introspection alone" |
| Missing | schema acquisition and model, operation catalog, per-field authz testing, cost-safe execution |

**Build (`core/graphql_intel.py`):**

1. **Schema acquisition:** introspection when enabled; when disabled,
   reconstruct from (a) operations captured in the corpus, (b) persisted
   query manifests / client bundles, (c) field-suggestion error messages
   (the clairvoyance technique; tool not installed — implement a small,
   rate-limited version or install it).
2. **Schema model:** types, fields, arguments, which fields return objects
   owned by a user (`node(id:)`, `user(id:)`, connections), mutations grouped
   by sensitivity.
3. **Authorization:** every resolver path becomes a corpus entry, so the same
   differential engine runs BOLA (object-returning fields with B's ID) and
   BFLA (mutations/fields seen only under privileged identities) per field,
   including nested paths that bypass a checked top-level resolver.
4. **Cost safety:** depth/alias/batch limits enforced client-side; batching
   and alias amplification are classified as `load` by the escalation gate
   (approval), never used for brute force.
5. **Evidence:** the exact operation document + variables + response excerpt
   with B's marker; introspection output alone is only ever a lead.

---

## Phase 3 — Business Logic Analysis

| | |
|---|---|
| Exists | Proof gate requires an attested recording for `business logic` and `race condition`; gotchas race-condition rules (before/after persisted state) |
| Missing | workflow model, invariants, experiment runner, state snapshots |

**Build (`core/logic.py`):**

1. **Workflow model:** sequences of corpus exchanges per identity grouped
   into flows (signup → verify → cart → coupon → checkout → pay), with the
   state each step reads/writes.
2. **Invariants written by the hunter** (the agent may *suggest* them, the
   hunter accepts): "coupon single-use", "price comes from server", "refund ≤
   paid", "step 3 requires step 2". Stored per program.
3. **Hypotheses:** the AI proposes concrete violations of an accepted
   invariant (skip step, replay step, reorder, modify client-held value,
   concurrent duplicate) — each is a lead with its planned experiment.
4. **Experiments:** run only on test accounts, after approval, with small
   bounded concurrency for race cases (gotchas: a small burst proves it;
   volume is abuse). Each experiment captures **state snapshots** (read-only
   GETs before and after) that become the observed evidence.
5. **Confirmation:** the persisted end state (balance, redemption count,
   entitlement) violates the invariant — not response codes.

---

## Phase 4 — Burp Suite integration

| | |
|---|---|
| Exists | Burp Suite.app installed; HackBot can `/attest` Burp-exported files; `validator.md` describes an *optional* Burp MCP flow, but no Burp MCP server is configured |
| Missing | traffic import, upstream proxying, live Burp access |

**Build in three independent steps:**

1. **Import (no Burp extension needed):** Burp "Save items" XML and HAR →
   corpus (0.2). Imported responses are attested automatically (hash
   recorded), so they count as `recorded` evidence.
2. **Upstream proxy:** route HackBot `HttpClient` and tool traffic through
   Burp (`ScanConfig.proxy` already exists) so every request HackBot sends is
   visible in Burp history — the hunter keeps the full audit trail.
3. **Live access:** PortSwigger publishes an MCP server extension for Burp;
   verify its current version and tool list before relying on it. If
   suitable, register it in Claude Code for the `validator` agent's Gate 0
   step (pull exact request/response from history). HackBot itself keeps
   using import + upstream proxy, so it never depends on Burp being open.

Out-of-band confirmation (Collaborator) needs Burp Pro; the existing
`/oob` interactsh workflow on the Claude side is the alternative.

---

## Phase 5 — Claude Code MCP integration

| | |
|---|---|
| Exists | One-way handoff packet + `/hackbot-validate` command |
| Missing | live, structured access from Claude Code agents to HackBot state |

**Build `hackbot/mcp_server.py`** (Python MCP SDK, stdio transport,
registered for the HUNTIX project only):

| Tool | Purpose | Side effects |
|---|---|---|
| `scope_check(command_or_url)` | ask the enforced policy | none |
| `corpus_search(query)` | endpoints / params / IDs | none |
| `identities_list()` | names, roles, tenants (no secrets) | none |
| `findings_list()` / `finding_get(n)` | full finding + proof + validation | none |
| `proof_evaluate(n)` / `prevalidate(n)` | re-run gates | none |
| `handoff_export(n)` | write packet | local file |
| `authz_diff_plan(exchange_id)` | propose differential tests | none |
| `authz_diff_run(plan_id)` | execute read-only plan | network, scope-gated |

Rules:

- Any tool that would need `on_approve` returns `approval_required` with the
  prompt text; approval happens in HackBot (CLI/GUI queue), never by the
  model. MCP cannot be a bypass for the gates.
- This direction is Claude Code → HackBot. It does not route HackBot's own
  LLM calls through Claude Code (that integration was blocked earlier and is
  not revisited).
- `chain-builder` and `recon-ranker` agents can then read real corpus and
  findings instead of free-text descriptions; `validator` reads
  `finding_get` instead of the static packet.

---

## Order, size, and how each step is tested

| # | Step | Depends on | Size | Test bed (local only) |
|---|---|---|---|---|
| 0 | GUI approval queue + attest/replay/review UI | — | M | unit + Flask client |
| 0.1 | Identity Vault + redaction | — | M | unit |
| 0.2 | Request Corpus + HAR/OpenAPI import | — | M | fixtures |
| 0.3 | Differential replay engine | 0.1, 0.2 | M | OWASP crAPI (Docker) |
| 1.1 | BOLA/IDOR | 0.3 | M | crAPI, Juice Shop |
| 1.2 | BFLA | 0.3 | M | crAPI |
| 1.3 | Multi-account extras (tenants, lifecycle) | 0.1 | S | crAPI |
| 4.1–4.2 | Burp import + upstream proxy | 0.2 | S | Burp exports of the labs |
| 5 | MCP server | 0.2, 0.3 | M | MCP client test harness |
| 2 | GraphQL intelligence | 0.2, 0.3 | L | DVGA (Damn Vulnerable GraphQL App) |
| 3 | Business logic | 0.1–0.3 | L | Juice Shop / crAPI flows |
| 4.3 | Burp MCP (live) | 5 | S | after verifying the extension |

Every step ships with: unit tests, a regression run, an integration test
against a **local** intentionally-vulnerable lab (never a real program), and
an acceptance check that its confirmed findings pass the existing proof gate
and pre-validation without manual editing.

## Success metrics (measure, don't assume)

- Lead → confirmed conversion rate per module.
- Confirmed findings that later get `false_positive` on human review (target: ~0).
- `/hackbot-validate` PASS rate of exported packets.
- Accepted / N/A ratio on submitted reports (tracked by the hunter).
