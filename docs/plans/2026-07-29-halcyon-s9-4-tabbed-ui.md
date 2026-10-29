# Halcyon S9.4 — Tabbed UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild `halcyon/templates/chat.html` into a six-layer tabbed lab UI with a per-tab guardrail sidebar, a five-provider model-config modal, browser panels for M6/M7/M8, an attack-board link, and a per-surface new-conversation reset — all binding to existing routes.

**Architecture:** Pure frontend slice. One self-contained Jinja template (HTML + inline `<style>` + one nonce'd `<script>`) served by the unchanged `/chat` handler. Tab switching and sidebar rendering are client-side; every panel calls an endpoint that already exists in `halcyon/web.py`. The only server touch is passing `settings.mode` into the template render so the sidebar can seed default levels.

**Tech Stack:** FastAPI + Jinja2 (server render), vanilla JS (no build step, no framework, no external scripts — CSP forbids them), pytest + `fastapi.testclient.TestClient` for render-contract tests.

## Global Constraints

- **No endpoint, guard, validator, or audit-log change.** Only `halcyon/templates/chat.html` is rebuilt; `halcyon/web.py` gets a one-line render-kwarg addition (`mode=settings.mode`). Nothing else server-side changes.
- **Deterministic test suite must stay green.** Run `pytest` (Stub LLM/ToolLLM); no live model calls in tests.
- **Safe rendering discipline:** all model/user output via `textContent`. The ONLY `|safe`/raw-HTML path is the M2 greeting sink `{{ display_name_html | safe }}` inside `<span id="dn">`. No `innerHTML` anywhere in the JS.
- **Preserve these exact markers** (pinned by existing tests): `<div id="cfg" data-encoding="{{ output_encoding }}">`, `<span id="dn">{{ display_name_html | safe }}</span>`, `<script nonce="{{ nonce }}">`, element ids `kbsubmit` and `askbtn`.
- **Provider values** (exact strings the model factory accepts): `local`, `anthropic`, `openai`, `gemini`, `xai`.
- **Model-field seed defaults** (editable): local `llama3.1:8b` · anthropic `claude-haiku-4-5` · openai `gpt-5.6-luna` · gemini `gemini-3.5-flash-lite` · xai `grok-4.3`.
- **CSP:** the single inline `<script>` must carry `nonce="{{ nonce }}"`. No external `.js`/`.css`, no inline event-handler attributes (`onclick="…"` in HTML) — wire everything from the nonce'd script.
- **Session id:** `?session=` query param, default `"dev"`.

---

## Layer → module → endpoint reference

| Tab | Layer | Module(s) | Endpoints | Guardrail toggle(s) |
|-----|-------|-----------|-----------|---------------------|
| L0 | Chatbot | M1, M2 | `/api/chat`, `/api/profile`, `/reset/m1` | M1, M2 |
| L1 | RAG | M3 | `/api/kb`, `/api/ask` | M3 |
| L2 | Agent | M4, M5 | `/submit/m4`, `/api/agent`, `/reset/m5` | M5 only (M4 has no runtime guard) |
| L3 | MCP | M6 | `/api/mcp-agent` | M6 (disabled — process-wide this release) |
| L4 | Multi-agent | M7 | `/api/dispute` | M7 |
| L5 | Production | M8 | `/api/guarded-chat` | M8 |

Endpoint request/response contracts (from `halcyon/web.py`, all unchanged):
- `POST /api/chat {session_id, message}` → `{reply}`
- `POST /api/profile {session_id, display_name}` → `{status}`
- `POST /api/kb {session_id, text}` → `{status}`
- `POST /api/ask {session_id, query}` → `{reply}`
- `POST /submit/m4 {session_id, finding_type, value}` → `{correct}` (finding_type ∈ `malicious_artifact`, `vulnerable_dependency`)
- `POST /api/agent {session_id, message}` → `{reply, tool_calls:[{name,args}]}`
- `POST /api/mcp-agent {session_id, message}` → `{reply, tool_calls:[{name,args}]}`
- `POST /api/dispute {session_id, dispute_text, account, amount}` → `{decision, transcript:[{from,content}]}`
- `POST /api/guarded-chat {session_id, message}` → `{reply}`
- `POST /reset/{module} {session_id}` → `{status, module}`
- `POST /api/level {session_id, module, level}` → `{status, module, level}` (level ∈ `L1`,`L2`)
- `GET /api/level?session=` → `{module: level, …}` (only explicit overrides; may be `{}`)
- `POST /api/config {session_id, provider, model, api_key}` → `{status, provider, model}`
- `GET /api/config?session=` → `{provider, model}` (never the key)

---

### Task 1: Rebuild the tabbed UI (render-contract test + template)

Test and template land together — the template plus its render-contract test are one reviewable unit (a reviewer can't meaningfully approve half a Jinja template). This is a full red→green→commit cycle.

**Files:**
- Modify: `halcyon/web.py` (one line — the `/chat` render kwargs, ~line 260)
- Rewrite: `halcyon/templates/chat.html` (full replacement)
- Modify: `tests/test_web.py` (add render-contract test; update the stale model-selector test)

**Interfaces:**
- Consumes (existing, unchanged): the `make_client(env, reply)` helper at the top of `tests/test_web.py` returning `(TestClient, store)`; all endpoints in the reference table above.
- Produces: a `/chat` HTML document containing the markers asserted below. No new Python symbols.

- [ ] **Step 1: Write the failing render-contract tests**

Add these two functions to `tests/test_web.py`, and REPLACE the existing `test_chat_page_has_model_selector` (it asserts the removed `"remote"` control):

```python
def test_chat_page_has_model_modal():
    # Replaces the old local/remote selector assertion: the config UI is now a
    # five-provider modal, not a two-option inline select.
    client, _ = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    text = client.get("/chat").text
    assert 'id="cfg-provider"' in text
    low = text.lower()
    for provider in ("local", "anthropic", "openai", "gemini", "xai"):
        assert provider in low, f"provider {provider} missing from model modal"
    assert "remote" not in low  # the stale control is gone


def test_chat_page_renders_all_layer_tabs_and_panels():
    client, _ = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    text = client.get("/chat", params={"session": "p1"}).text
    # six layer tabs + panels
    for layer in ("L0", "L1", "L2", "L3", "L4", "L5"):
        assert f'data-tab="{layer}"' in text, f"missing tab {layer}"
        assert f'data-layer="{layer}"' in text, f"missing panel {layer}"
    # every panel's key control ids are present
    for el in (
        'id="msg"', 'id="chat-newconv"', 'id="setname"',      # L0
        'id="kbsubmit"', 'id="askbtn"',                        # L1
        'id="m4hash"', 'id="m4pkg"', 'id="m5send"',            # L2
        'id="mcpsend"',                                        # L3
        'id="dsend"', 'id="dtext"',                            # L4
        'id="gsend"',                                          # L5
        'id="sidebar"', 'id="model-modal"',                   # chrome
    ):
        assert el in text, f"missing element {el}"
    # attack-board link + MCP inspector hint
    assert 'href="/board"' in text
    assert "modelcontextprotocol/inspector" in text
```

- [ ] **Step 2: Run the new/updated tests to verify they fail**

Run: `cd /Users/kkmookhey/Projects/eiger && python -m pytest tests/test_web.py::test_chat_page_has_model_modal tests/test_web.py::test_chat_page_renders_all_layer_tabs_and_panels -v`
Expected: FAIL — the current template has no `data-tab`, `cfg-provider`, `mcpsend`, `dsend`, `/board` link, or inspector hint.

- [ ] **Step 3: Pass `mode` into the `/chat` render**

In `halcyon/web.py`, the `chat_page` handler (~line 256-264) currently renders with `output_encoding`, `display_name_html`, `nonce`. Add `mode=settings.mode`:

```python
    @app.get("/chat", response_class=HTMLResponse)
    def chat_page(request: Request, session: str = "dev") -> str:
        name = store.get_profile(session)
        eff = effective_settings(settings, sess, session, "m2")
        return templates.get_template("chat.html").render(
            output_encoding="on" if eff.sec_output_encoding else "off",
            display_name_html=guards.encode_output(name, eff),
            nonce=request.state.csp_nonce,
            mode=settings.mode,
        )
```

- [ ] **Step 4: Rewrite `halcyon/templates/chat.html`**

Replace the entire file with:

```html
<!doctype html>
<title>Halo — Halcyon Lab</title>
<style>
  :root { --accent: #0b5cad; --line: #d7dbe0; --bg: #fafbfc; --muted: #6b7280; }
  * { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; margin: 0; color: #1a1d21; }
  header#topbar { display: flex; align-items: center; justify-content: space-between;
    padding: .6rem 1rem; border-bottom: 1px solid var(--line); }
  header#topbar .brand { font-weight: 600; }
  header#topbar nav { display: flex; align-items: center; gap: 1rem; }
  header#topbar a { color: var(--accent); text-decoration: none; font-size: .9rem; }
  #model-btn { font: inherit; font-size: .85rem; padding: .35rem .7rem; cursor: pointer;
    border: 1px solid var(--line); border-radius: 6px; background: #fff; }
  nav#tabs { display: flex; gap: .25rem; padding: .5rem 1rem 0; border-bottom: 1px solid var(--line);
    overflow-x: auto; }
  nav#tabs .tab { font: inherit; font-size: .9rem; padding: .5rem .8rem; cursor: pointer;
    border: 1px solid transparent; border-bottom: none; border-radius: 6px 6px 0 0; background: none;
    color: var(--muted); white-space: nowrap; }
  nav#tabs .tab.active { color: #1a1d21; border-color: var(--line); background: #fff;
    margin-bottom: -1px; font-weight: 600; }
  #body { display: flex; gap: 1rem; max-width: 960px; margin: 1rem auto; padding: 0 1rem; }
  #sidebar { flex: 0 0 190px; border: 1px solid var(--line); border-radius: 8px; padding: .8rem;
    height: fit-content; background: var(--bg); }
  #sidebar h3 { margin: 0 0 .6rem; font-size: .8rem; text-transform: uppercase; color: var(--muted);
    letter-spacing: .04em; }
  .sb-row { display: flex; align-items: center; justify-content: space-between; margin: .4rem 0;
    font-size: .85rem; }
  .level-toggle { font: inherit; font-size: .8rem; min-width: 2.4rem; padding: .2rem .5rem; cursor: pointer;
    border: 1px solid var(--line); border-radius: 999px; background: #fff; }
  .level-toggle[data-level="L2"] { background: var(--accent); color: #fff; border-color: var(--accent); }
  .level-toggle:disabled { opacity: .5; cursor: not-allowed; }
  #panels { flex: 1; min-width: 0; }
  #panels section h2 { font-size: 1.05rem; margin: 0 0 .5rem; }
  #panels section h3 { font-size: .95rem; margin: 1.2rem 0 .4rem; }
  .row { display: flex; gap: .5rem; margin: .5rem 0; flex-wrap: wrap; }
  .row input, .row select, textarea { padding: .55rem .65rem; font: inherit; border: 1px solid #bbb;
    border-radius: 6px; }
  .row input[type=text], .row input:not([type]) { flex: 1; min-width: 12rem; }
  textarea { width: 100%; font-family: inherit; }
  button { font: inherit; }
  .row button { padding: .55rem 1rem; cursor: pointer; border: 1px solid #bbb; border-radius: 6px;
    background: #fff; }
  .row button[disabled] { opacity: .5; cursor: default; }
  .log { border: 1px solid var(--line); border-radius: 8px; padding: 1rem; height: 320px;
    overflow-y: auto; background: var(--bg); }
  .log p { margin: .35rem 0; line-height: 1.4; }
  .you { color: var(--accent); } .halo { color: #222; } .sys { color: #888; font-style: italic; }
  .out { border: 1px solid var(--line); border-radius: 8px; padding: 1rem; margin-top: .5rem;
    background: var(--bg); min-height: 1.4em; white-space: pre-wrap; }
  #greeting { margin: .3rem 0 .8rem; }
  .modal { position: fixed; inset: 0; background: rgba(0,0,0,.35); display: flex;
    align-items: center; justify-content: center; }
  .modal[hidden] { display: none; }
  .modal-box { background: #fff; border-radius: 10px; padding: 1.4rem; width: 22rem; max-width: 92vw; }
  .modal-box h3 { margin: 0 0 .8rem; }
  .modal-box label { display: block; margin: .6rem 0 .15rem; font-size: .85rem; color: var(--muted); }
  .modal-box select, .modal-box input { width: 100%; padding: .5rem .6rem; font: inherit;
    border: 1px solid #bbb; border-radius: 6px; }
  .modal-actions { display: flex; gap: .5rem; margin-top: 1rem; }
  .modal-actions button { flex: 1; padding: .55rem; cursor: pointer; border-radius: 6px;
    border: 1px solid #bbb; background: #fff; }
  #cfg-save { background: var(--accent); color: #fff; border-color: var(--accent); }
  .hint { font-size: .78rem; color: var(--muted); margin: .8rem 0 0; }
  details#inspector-hint { margin-top: 1rem; font-size: .88rem; }
  details#inspector-hint pre { background: var(--bg); border: 1px solid var(--line); border-radius: 6px;
    padding: .6rem; overflow-x: auto; }
</style>

<div id="cfg" data-encoding="{{ output_encoding }}" data-mode="{{ mode }}"></div>

<header id="topbar">
  <span class="brand">Halcyon — Halo Lab</span>
  <nav>
    <a id="board-link" href="/board" target="_blank" rel="noopener">Attack board</a>
    <button id="model-btn" type="button">⚙ <span id="model-label">local · llama3.1:8b</span></button>
  </nav>
</header>

<nav id="tabs">
  <button class="tab" data-tab="L0" type="button">L0 Chatbot</button>
  <button class="tab" data-tab="L1" type="button">L1 RAG</button>
  <button class="tab" data-tab="L2" type="button">L2 Agent</button>
  <button class="tab" data-tab="L3" type="button">L3 MCP</button>
  <button class="tab" data-tab="L4" type="button">L4 Multi-agent</button>
  <button class="tab" data-tab="L5" type="button">L5 Production</button>
</nav>

<div id="body">
  <aside id="sidebar"></aside>
  <main id="panels">

    <section data-layer="L0">
      <h2>L0 — Chatbot (M1 prompt injection · M2 output handling)</h2>
      <div id="greeting">Welcome, <span id="dn">{{ display_name_html | safe }}</span></div>
      <div class="row">
        <input id="dname" type="text" placeholder="Display name" />
        <button id="setname" type="button">Set name</button>
      </div>
      <div id="log" class="log"></div>
      <form id="chatform" class="row">
        <input id="msg" type="text" placeholder="Message Halo…" autocomplete="off" autofocus />
        <button id="send" type="submit">Send</button>
        <button id="chat-newconv" type="button">New conversation</button>
      </form>
    </section>

    <section data-layer="L1" hidden>
      <h2>L1 — RAG (M3 knowledge-base poisoning)</h2>
      <textarea id="kbtext" rows="4" placeholder="Submit a note to the community KB…"></textarea>
      <div class="row">
        <button id="kbsubmit" type="button">Submit to community KB</button>
        <span id="kbstatus"></span>
      </div>
      <div class="row">
        <input id="askq" type="text" placeholder="Ask Halo (RAG)…" autocomplete="off" />
        <button id="askbtn" type="button">Ask Halo (RAG)</button>
      </div>
      <div id="ragout" class="out"></div>
    </section>

    <section data-layer="L2" hidden>
      <h2>L2 — Agent (M4 supply-chain · M5 tool misuse)</h2>
      <h3>M4 — Supply-chain audit</h3>
      <p>Audit <code>labs/m4/</code>. Run
        <code>python -m halcyon.scan_artifact labs/m4/artifacts/*</code> to find the poisoned
        model; check <code>labs/m4/requirements-vulnerable.txt</code> for a vulnerable pin.</p>
      <div class="row">
        <input id="m4hash" type="text" placeholder="Artifact sha256" />
        <button id="m4hashbtn" type="button">Submit artifact</button>
      </div>
      <div class="row">
        <input id="m4pkg" type="text" placeholder="Vulnerable package" />
        <button id="m4pkgbtn" type="button">Submit package</button>
      </div>
      <span id="m4status"></span>
      <h3>M5 — Agent (Halo can act)</h3>
      <p>Click Reset to seed your accounts (acct-me is yours; acct-victim/acct-attacker are not).
        Then ask Halo to move money to an account you don't own.</p>
      <div class="row">
        <button id="m5reset" type="button">Reset accounts</button>
        <span id="m5status"></span>
      </div>
      <div class="row">
        <input id="m5msg" type="text" placeholder="Ask Halo to act…" autocomplete="off" />
        <button id="m5send" type="button">Ask the agent</button>
      </div>
      <div id="m5out" class="out"></div>
    </section>

    <section data-layer="L3" hidden>
      <h2>L3 — MCP (M6 tool-description poisoning · token scope)</h2>
      <p>Halo calls the core-banking and CRM tools over MCP servers.</p>
      <div class="row">
        <input id="mcpmsg" type="text" placeholder="Ask the MCP agent…" autocomplete="off" />
        <button id="mcpsend" type="button">Ask</button>
      </div>
      <div id="mcpout" class="out"></div>
      <details id="inspector-hint">
        <summary>See the protocol — MCP Inspector</summary>
        <p>Point the inspector at the exposed MCP ports to watch tool discovery and calls:</p>
        <pre>npx @modelcontextprotocol/inspector</pre>
      </details>
    </section>

    <section data-layer="L4" hidden>
      <h2>L4 — Multi-agent (M7 inter-agent trust)</h2>
      <p>File a dispute; the triage and adjudicator agents exchange signed messages.</p>
      <div class="row"><input id="dacct" type="text" placeholder="Account (e.g. acct-me)" /></div>
      <div class="row"><input id="damt" type="number" placeholder="Amount" /></div>
      <textarea id="dtext" rows="3" placeholder="Dispute text…"></textarea>
      <div class="row"><button id="dsend" type="button">File dispute</button></div>
      <div id="dout" class="out"></div>
    </section>

    <section data-layer="L5" hidden>
      <h2>L5 — Production (M8 guardrails / prompt firewall)</h2>
      <p>Chat through the guardrail stack. Flip M8 to L2 to arm the input/output filters.</p>
      <div class="row">
        <input id="gmsg" type="text" placeholder="Message guarded Halo…" autocomplete="off" />
        <button id="gsend" type="button">Send</button>
      </div>
      <div id="gout" class="out"></div>
    </section>

  </main>
</div>

<div id="model-modal" class="modal" hidden>
  <div class="modal-box">
    <h3>Model configuration</h3>
    <label for="cfg-provider">Provider</label>
    <select id="cfg-provider">
      <option value="local">Local (Ollama)</option>
      <option value="anthropic">Anthropic</option>
      <option value="openai">OpenAI</option>
      <option value="gemini">Gemini</option>
      <option value="xai">xAI (Grok)</option>
    </select>
    <label for="cfg-model">Model</label>
    <input id="cfg-model" type="text" value="llama3.1:8b" />
    <label for="cfg-key">API key</label>
    <input id="cfg-key" type="password" placeholder="not stored in the audit log" />
    <div class="modal-actions">
      <button id="cfg-save" type="button">Save</button>
      <button id="cfg-cancel" type="button">Cancel</button>
    </div>
    <p class="hint">Local needs no key. Keys are session-scoped and never written to the audit log or the attack board.</p>
  </div>
</div>

<script nonce="{{ nonce }}">
  const sid = new URLSearchParams(location.search).get("session") || "dev";
  const cfgEl = document.getElementById("cfg");
  const baseLevel = cfgEl.dataset.mode === "secure" ? "L2" : "L1";

  // ---- per-tab guardrail sidebar ----
  const TAB_MODULES = {
    L0: [{ m: "m1", label: "M1 injection" }, { m: "m2", label: "M2 output" }],
    L1: [{ m: "m3", label: "M3 RAG" }],
    L2: [{ m: "m5", label: "M5 tools" }],              // M4 has no runtime guard
    L3: [{ m: "m6", label: "M6 MCP", disabled: true }],
    L4: [{ m: "m7", label: "M7 multi-agent" }],
    L5: [{ m: "m8", label: "M8 guardrails" }],
  };
  let levels = {};                                     // module -> "L1" | "L2"
  const sidebar = document.getElementById("sidebar");
  const levelOf = (m) => levels[m] || baseLevel;

  function renderSidebar(tab) {
    sidebar.textContent = "";
    const h = document.createElement("h3");
    h.textContent = "Guardrails";
    sidebar.appendChild(h);
    for (const { m, label, disabled } of TAB_MODULES[tab]) {
      const row = document.createElement("div");
      row.className = "sb-row";
      const name = document.createElement("span");
      name.textContent = label;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "level-toggle";
      const paint = () => { btn.textContent = levelOf(m); btn.dataset.level = levelOf(m); };
      paint();
      if (disabled) {
        btn.disabled = true;
        btn.title = "MCP guardrail level is process-wide this release";
      } else {
        btn.onclick = async () => {
          const next = levelOf(m) === "L1" ? "L2" : "L1";
          btn.disabled = true;
          try {
            await fetch("/api/level", {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ session_id: sid, module: m, level: next }),
            });
            levels[m] = next; paint();
          } finally { btn.disabled = false; }
        };
      }
      row.appendChild(name); row.appendChild(btn); sidebar.appendChild(row);
    }
  }

  const tabs = document.querySelectorAll("#tabs .tab");
  const sections = document.querySelectorAll("#panels section");
  function activate(tab) {
    tabs.forEach((t) => t.classList.toggle("active", t.dataset.tab === tab));
    sections.forEach((s) => { s.hidden = s.dataset.layer !== tab; });
    renderSidebar(tab);
  }
  tabs.forEach((t) => { t.onclick = () => activate(t.dataset.tab); });

  // ---- model-config modal ----
  const DEFAULT_MODEL = {
    local: "llama3.1:8b", anthropic: "claude-haiku-4-5",
    openai: "gpt-5.6-luna", gemini: "gemini-3.5-flash-lite", xai: "grok-4.3",
  };
  const modal = document.getElementById("model-modal");
  const provSel = document.getElementById("cfg-provider");
  const modelIn = document.getElementById("cfg-model");
  const keyIn = document.getElementById("cfg-key");
  const modelLabel = document.getElementById("model-label");
  document.getElementById("model-btn").onclick = () => { modal.hidden = false; };
  document.getElementById("cfg-cancel").onclick = () => { modal.hidden = true; };
  provSel.onchange = () => { modelIn.value = DEFAULT_MODEL[provSel.value] || ""; };
  document.getElementById("cfg-save").onclick = async () => {
    const body = { session_id: sid, provider: provSel.value, model: modelIn.value, api_key: keyIn.value };
    try {
      const r = await fetch("/api/config", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await r.json();
      modelLabel.textContent = (data.provider || provSel.value) + " · " + (data.model || modelIn.value);
    } catch (err) {
      modelLabel.textContent = "save failed";
    } finally {
      keyIn.value = "";              // never keep the key in the DOM
      modal.hidden = true;
    }
  };

  // ---- shared helpers ----
  function line(logEl, cls, who, text) {
    const p = document.createElement("p");
    p.className = cls; p.textContent = who + ": " + text;
    logEl.appendChild(p); logEl.scrollTop = logEl.scrollHeight;
    return p;
  }
  function renderAgent(outEl, data) {
    if (data.reply === undefined) { outEl.textContent = "error: " + JSON.stringify(data); return; }
    let text = data.reply;
    for (const call of data.tool_calls ?? []) {
      text += "\ntool: " + call.name + "(" + JSON.stringify(call.args) + ")";
    }
    outEl.textContent = text;
  }
  const postJSON = (url, body) => fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });

  // ---- L0 chat ----
  const log = document.getElementById("log");
  const msgEl = document.getElementById("msg");
  const sendBtn = document.getElementById("send");
  document.getElementById("setname").onclick = () => {
    postJSON("/api/profile", { session_id: sid, display_name: document.getElementById("dname").value })
      .then(() => location.reload());
  };
  document.getElementById("chatform").onsubmit = async (e) => {
    e.preventDefault();
    const msg = msgEl.value.trim();
    if (!msg) return;
    line(log, "you", "You", msg);
    msgEl.value = ""; sendBtn.disabled = true;
    const pending = line(log, "sys", "Halo", "typing…");
    try {
      const r = await postJSON("/api/chat", { session_id: sid, message: msg });
      const data = await r.json();
      pending.remove();
      line(log, "halo", "Halo", data.reply ?? ("error: " + JSON.stringify(data)));
    } catch (err) {
      pending.remove(); line(log, "sys", "Halo", "request failed — " + err);
    } finally {
      sendBtn.disabled = false; msgEl.focus();
    }
  };
  document.getElementById("chat-newconv").onclick = async () => {
    await postJSON("/reset/m1", { session_id: sid });
    log.textContent = "";
  };

  // ---- L1 RAG ----
  const kbstatus = document.getElementById("kbstatus");
  document.getElementById("kbsubmit").onclick = async () => {
    const t = document.getElementById("kbtext");
    if (!t.value.trim()) return;
    kbstatus.textContent = "";
    try {
      await postJSON("/api/kb", { session_id: sid, text: t.value });
      kbstatus.textContent = "submitted"; t.value = "";
    } catch (err) { kbstatus.textContent = "submit failed — " + err; }
  };
  const ragout = document.getElementById("ragout");
  document.getElementById("askbtn").onclick = async () => {
    const q = document.getElementById("askq");
    if (!q.value.trim()) return;
    ragout.textContent = "…";
    try {
      const r = await postJSON("/api/ask", { session_id: sid, query: q.value });
      const data = await r.json();
      ragout.textContent = data.reply ?? ("error: " + JSON.stringify(data));
    } catch (err) { ragout.textContent = "request failed — " + err; }
  };

  // ---- L2 M4 + M5 ----
  const m4status = document.getElementById("m4status");
  async function submitM4(findingType, value) {
    const r = await postJSON("/submit/m4", { session_id: sid, finding_type: findingType, value: value });
    return (await r.json()).correct;
  }
  document.getElementById("m4hashbtn").onclick = async () => {
    try {
      const ok = await submitM4("malicious_artifact", document.getElementById("m4hash").value);
      m4status.textContent = "artifact: " + (ok ? "correct" : "incorrect");
    } catch (err) { m4status.textContent = "artifact: request failed — " + err; }
  };
  document.getElementById("m4pkgbtn").onclick = async () => {
    try {
      const ok = await submitM4("vulnerable_dependency", document.getElementById("m4pkg").value);
      m4status.textContent = "package: " + (ok ? "correct" : "incorrect");
    } catch (err) { m4status.textContent = "package: request failed — " + err; }
  };
  const m5out = document.getElementById("m5out");
  const m5status = document.getElementById("m5status");
  document.getElementById("m5reset").onclick = async () => {
    m5status.textContent = "";
    try {
      await postJSON("/reset/m5", { session_id: sid });
      m5status.textContent = "accounts reset";
    } catch (err) { m5status.textContent = "reset failed — " + err; }
  };
  document.getElementById("m5send").onclick = async () => {
    const m = document.getElementById("m5msg");
    if (!m.value.trim()) return;
    m5out.textContent = "…";
    try {
      const r = await postJSON("/api/agent", { session_id: sid, message: m.value });
      renderAgent(m5out, await r.json());
    } catch (err) { m5out.textContent = "request failed — " + err; }
  };

  // ---- L3 MCP ----
  const mcpout = document.getElementById("mcpout");
  document.getElementById("mcpsend").onclick = async () => {
    const m = document.getElementById("mcpmsg");
    if (!m.value.trim()) return;
    mcpout.textContent = "…";
    try {
      const r = await postJSON("/api/mcp-agent", { session_id: sid, message: m.value });
      renderAgent(mcpout, await r.json());
    } catch (err) { mcpout.textContent = "request failed — " + err; }
  };

  // ---- L4 dispute ----
  const dout = document.getElementById("dout");
  document.getElementById("dsend").onclick = async () => {
    dout.textContent = "…";
    const body = {
      session_id: sid,
      dispute_text: document.getElementById("dtext").value,
      account: document.getElementById("dacct").value,
      amount: parseInt(document.getElementById("damt").value || "0", 10),
    };
    try {
      const r = await postJSON("/api/dispute", body);
      const data = await r.json();
      if (data.decision === undefined) { dout.textContent = "error: " + JSON.stringify(data); return; }
      let text = "decision: " + data.decision;
      for (const m of data.transcript ?? []) text += "\n[" + m.from + "] " + m.content;
      dout.textContent = text;
    } catch (err) { dout.textContent = "request failed — " + err; }
  };

  // ---- L5 guarded chat ----
  const gout = document.getElementById("gout");
  document.getElementById("gsend").onclick = async () => {
    const m = document.getElementById("gmsg");
    if (!m.value.trim()) return;
    gout.textContent = "…";
    try {
      const r = await postJSON("/api/guarded-chat", { session_id: sid, message: m.value });
      const data = await r.json();
      gout.textContent = data.reply ?? ("error: " + JSON.stringify(data));
    } catch (err) { gout.textContent = "request failed — " + err; }
  };

  // ---- bootstrap ----
  (async () => {
    try {
      const lv = await (await fetch("/api/level?session=" + encodeURIComponent(sid))).json();
      if (lv && typeof lv === "object" && !lv.error) levels = lv;
    } catch (e) { /* leave defaults */ }
    try {
      const c = await (await fetch("/api/config?session=" + encodeURIComponent(sid))).json();
      if (c && c.provider) {
        modelLabel.textContent = c.provider + " · " + (c.model || DEFAULT_MODEL[c.provider] || "");
      }
    } catch (e) { /* leave default label */ }
    activate("L0");
  })();
</script>
```

- [ ] **Step 5: Run the full suite to verify green**

Run: `cd /Users/kkmookhey/Projects/eiger && python -m pytest tests/test_web.py -v && python -m pytest`
Expected: the two new tests PASS; the preserved tests still PASS —
`test_chat_page_has_rag_panel` (kbsubmit/askbtn), `test_chat_page_exposes_encoding_flag`
(`data-encoding` on/off), `test_secure_csp_nonce_matches_app_script` (nonce on the script),
`test_display_name_rendered_raw_when_vulnerable_escaped_when_secure` (M2 sink), `test_csp_header_only_in_secure`.
Full suite green.

- [ ] **Step 6: Lint/type gates**

Run: `cd /Users/kkmookhey/Projects/eiger && ruff check halcyon tests && mypy halcyon`
Expected: clean (the only Python change is one render kwarg).

- [ ] **Step 7: Commit**

```bash
cd /Users/kkmookhey/Projects/eiger
git add halcyon/templates/chat.html halcyon/web.py tests/test_web.py
git commit -m "feat(s9.4): tabbed layer UI with guardrail sidebar + model modal

Rebuild chat.html into six layer tabs (L0-L5) with per-tab L1/L2
guardrail toggles (/api/level), a five-provider model-config modal
(/api/config), browser panels for M6/M7/M8, an attack-board link, and a
per-surface new-conversation reset. Pass settings.mode into the render so
the sidebar seeds default levels. Preserves the M2 XSS sink, CSP nonce,
and data-encoding flag. Frontend-only; no endpoint/guard/validator change.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Manual verification sweep on the running stack

No code. Drive the real UI to confirm behavior the render-smoke test can't (interaction, level-flip taking effect, key non-echo). This is the design doc's §8 manual sweep.

**Files:** none.

- [ ] **Step 1: Bring up the stack**

Run: `cd /Users/kkmookhey/Projects/eiger && docker compose -p halcyon up -d` (or confirm it's already up — web on `:8010`). Then open `http://localhost:8010/chat?session=verify1`.

- [ ] **Step 2: Tab + sidebar**

Click each of L0–L5. Confirm: the panel swaps; the sidebar shows only that layer's module toggle(s); L2 shows M5 only (no M4 toggle); L3's M6 toggle is greyed out with the process-wide tooltip on hover.

- [ ] **Step 3: L0 multi-turn + new conversation**

On L0, send 3 messages; confirm they accumulate in the log (multi-turn history is server-side). Click **New conversation**; confirm the log clears. Set a display name of `<b>hi</b>` and confirm the greeting renders it raw (vulnerable mode — the M2 sink) after reload.

- [ ] **Step 4: Level flip takes effect**

On L1, flip **M3** to L2 (toggle turns filled/blue). Submit a poisoning KB note and ask a question; confirm behavior reflects the guard being on (provenance/quarantine). Flip back to L1; confirm the next request is vulnerable again — no restart.

- [ ] **Step 5: Model modal round-trip**

Click the header model button. Switch provider to Anthropic; confirm the model field re-seeds to `claude-haiku-4-5`. Enter any key, Save. Confirm: the header label updates to `anthropic · claude-haiku-4-5`; reopening the modal shows the key field **empty** (never echoed); `GET /api/config?session=verify1` in the network tab returns provider+model with **no** api_key.

- [ ] **Step 6: New panels reach their endpoints**

L3: ask the MCP agent, confirm a reply + any `tool:` lines render. L4: file a dispute (account `acct-me`, amount `100`, some text), confirm decision + signed transcript lines. L5: send a guarded-chat message, confirm a reply. Expand the L3 Inspector hint and confirm the `npx` command shows.

- [ ] **Step 7: Attack board link**

Click **Attack board** in the header; confirm `/board` opens in a new tab and renders the JSON/board view.

- [ ] **Step 8: Record the result**

Note pass/fail per step. If any interaction fails, fix it in `chat.html` (re-run Task 1's tests to keep the render contract green) and re-verify. No commit needed unless a fix was made.

---

## Self-Review

**Spec coverage** (against `2026-07-29-halcyon-s9-4-tabbed-ui-design.md`):
- §3 layout (header/tabs/sidebar/modal) → Task 1 template. ✓
- §3 per-tab sidebar, M4 no-toggle, M6 disabled → `TAB_MODULES` + disabled branch. ✓
- §4 all six panels over existing endpoints → template + JS handlers. ✓
- §5 model modal, 5 providers, editable seed, key-never-returned → modal + save handler (clears key, label from response). ✓
- §6 safe rendering (textContent everywhere, sole `|safe` sink) → all outputs via `textContent`/`line`/`renderAgent`; sink preserved. ✓
- §7 bootstrap (session, GET /api/level, GET /api/config, default L0) → bootstrap IIFE. ✓
- §8 testing (render-smoke + manual) → Task 1 tests + Task 2 sweep. ✓
- Extras: board link, new-conversation, Inspector hint → all present + asserted. ✓

**Placeholder scan:** no TBD/TODO; every step has concrete code or an exact command. ✓

**Type/name consistency:** element ids in the template match every `getElementById`/assertion (`msg`, `chat-newconv`, `setname`, `kbsubmit`, `askbtn`, `m4hash`/`m4hashbtn`/`m4pkg`/`m4pkgbtn`, `m5reset`/`m5msg`/`m5send`, `mcpmsg`/`mcpsend`, `dtext`/`dacct`/`damt`/`dsend`, `gmsg`/`gsend`, `sidebar`, `model-modal`, `cfg-provider`/`cfg-model`/`cfg-key`/`cfg-save`/`cfg-cancel`, `model-btn`/`model-label`). Provider values (`local`/`anthropic`/`openai`/`gemini`/`xai`) match `to_litellm_model`. `data-tab`/`data-layer` values `L0`–`L5` are consistent between HTML and the `activate`/assertion loops. ✓
