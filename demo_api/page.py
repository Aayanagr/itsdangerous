"""Static HTML for the interactive signing page served at ``GET /``."""

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Demo signing service</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 42rem; margin: 2rem auto; padding: 0 1rem; color: #222; }
  textarea { width: 100%; box-sizing: border-box; min-height: 6rem; font-family: monospace; }
  input[type=text] { width: 100%; box-sizing: border-box; font-family: monospace; }
  pre { background: #f4f4f4; padding: 0.75rem; white-space: pre-wrap; word-break: break-all; }
  button { margin-top: 0.5rem; padding: 0.4rem 1rem; }
  .ok { color: #0a6b2d; }
  .err { color: #a11; }
</style>
</head>
<body>
<h1>Sign text</h1>
<p>Enter text, get a tamper-proof token. Paste a token below to verify it.</p>

<form id="sign-form">
  <label for="text">Text to sign</label>
  <textarea id="text" name="text" required></textarea>
  <button type="submit">Sign</button>
</form>
<pre id="token-out" aria-live="polite"></pre>

<h2>Verify</h2>
<form id="verify-form">
  <label for="token">Token</label>
  <input type="text" id="token" name="token" required>
  <button type="submit">Verify</button>
</form>
<pre id="verify-out" aria-live="polite"></pre>

<script>
async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let data = {};
  try { data = await res.json(); } catch (e) { data = { message: "Non-JSON response" }; }
  return { status: res.status, data: data };
}

function show(el, ok, text) {
  el.className = ok ? "ok" : "err";
  el.textContent = text;
}

document.getElementById("sign-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = document.getElementById("token-out");
  const text = document.getElementById("text").value;
  const r = await postJson("/sign", { payload: text });
  if (r.status === 200) {
    document.getElementById("token").value = r.data.token;
    show(out, true, r.data.token);
  } else {
    show(out, false, r.data.message || ("Error " + r.status));
  }
});

document.getElementById("verify-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = document.getElementById("verify-out");
  const token = document.getElementById("token").value;
  const r = await postJson("/verify", { token: token });
  if (r.status === 200) {
    show(out, true, "Valid. Payload: " + JSON.stringify(r.data.payload));
  } else {
    show(out, false, (r.data.error || "error") + ": " + (r.data.message || r.status));
  }
});
</script>
</body>
</html>
"""
