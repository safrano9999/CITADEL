<?php
/**
 * Hello World — CITADEL test page.
 * - LiteLLM: model discovery + chat dialog (if OPENAI_API_BASE is set)
 * - Postgres: connection check (if DB_HOST is set)
 */

// ── API endpoints ───────────────────────────────────────────────────────────

if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    $action = $_GET['api'];

    if ($action === 'status') {
        $status = ['hello' => true];

        // LiteLLM
        $llm_base = getenv('OPENAI_API_BASE') ?: '';
        $status['litellm'] = $llm_base !== '';
        $status['litellm_base'] = $llm_base;

        // Postgres
        $db_host = getenv('DB_HOST') ?: '';
        $status['postgres_configured'] = $db_host !== '';
        if ($db_host !== '') {
            $db_port = getenv('DB_PORT') ?: '5432';
            $db_user = getenv('DB_USER') ?: '';
            $db_pass = getenv('DB_PASSWORD') ?: '';
            $db_name = getenv('DB_NAME') ?: 'postgres';
            $conn_str = "host=$db_host port=$db_port dbname=$db_name user=$db_user password=$db_pass connect_timeout=3";
            $conn = @pg_connect($conn_str);
            if ($conn) {
                $status['postgres_ok'] = true;
                $ver = @pg_version($conn);
                $status['postgres_version'] = $ver['server'] ?? 'unknown';
                pg_close($conn);
            } else {
                $status['postgres_ok'] = false;
                $status['postgres_error'] = pg_last_error() ?: 'connection failed';
            }
        }

        echo json_encode($status);
        exit;
    }

    if ($action === 'models') {
        $base = rtrim(getenv('OPENAI_API_BASE') ?: '', '/');
        if (!$base) {
            http_response_code(404);
            echo json_encode(['error' => 'OPENAI_API_BASE not set']);
            exit;
        }
        $key = getenv('OPENAI_API_KEY') ?: '';
        $opts = ['http' => [
            'method' => 'GET',
            'timeout' => 5,
            'header' => $key ? "Authorization: Bearer $key\r\n" : '',
        ]];
        $ctx = stream_context_create($opts);
        $resp = @file_get_contents("$base/models", false, $ctx);
        if ($resp === false) {
            http_response_code(502);
            echo json_encode(['error' => 'Failed to reach LiteLLM']);
            exit;
        }
        echo $resp;
        exit;
    }

    if ($action === 'chat') {
        $input = json_decode(file_get_contents('php://input'), true);
        $base = rtrim(getenv('OPENAI_API_BASE') ?: '', '/');
        $key = getenv('OPENAI_API_KEY') ?: '';
        if (!$base) {
            http_response_code(404);
            echo json_encode(['error' => 'OPENAI_API_BASE not set']);
            exit;
        }
        $payload = json_encode([
            'model' => $input['model'] ?? '',
            'messages' => [['role' => 'user', 'content' => $input['text'] ?? '']],
            'max_tokens' => 2048,
        ]);
        $opts = ['http' => [
            'method' => 'POST',
            'timeout' => 60,
            'header' => "Content-Type: application/json\r\n"
                      . ($key ? "Authorization: Bearer $key\r\n" : ''),
            'content' => $payload,
        ]];
        $ctx = stream_context_create($opts);
        $resp = @file_get_contents("$base/chat/completions", false, $ctx);
        if ($resp === false) {
            http_response_code(502);
            echo json_encode(['error' => 'LiteLLM request failed']);
            exit;
        }
        echo $resp;
        exit;
    }

    http_response_code(404);
    echo json_encode(['error' => 'unknown endpoint']);
    exit;
}

// ── HTML frontend ───────────────────────────────────────────────────────────
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hello World — CITADEL</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #0f1117; color: #e0e0e0; padding: 24px; }
  h1 { font-size: 1.6rem; margin-bottom: 20px; color: #7eb8ff; }
  h2 { font-size: 1.1rem; margin-bottom: 12px; color: #a0c4ff; }

  .card { background: #1a1d28; border: 1px solid #2a2d38; border-radius: 8px;
          padding: 20px; margin-bottom: 20px; }

  /* Status badges */
  .status-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; font-size: 0.95rem; }
  .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px;
           border-radius: 4px; font-size: 0.85rem; font-weight: 600; }
  .badge.ok { background: #1a3a2a; color: #4ade80; }
  .badge.fail { background: #3a1a1a; color: #f87171; }
  .badge.na { background: #2a2a2a; color: #888; }

  /* LLM section */
  .llm-controls { display: flex; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
  select { background: #252830; color: #e0e0e0; border: 1px solid #3a3d48; border-radius: 4px;
           padding: 8px 12px; font-size: 0.9rem; min-width: 180px; }
  select:focus { border-color: #7eb8ff; outline: none; }

  .chat-area { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  @media (max-width: 700px) { .chat-area { grid-template-columns: 1fr; } }
  textarea { background: #252830; color: #e0e0e0; border: 1px solid #3a3d48; border-radius: 4px;
             padding: 10px; font-size: 0.9rem; resize: vertical; min-height: 120px; width: 100%;
             font-family: inherit; }
  textarea:focus { border-color: #7eb8ff; outline: none; }
  .response-box { background: #1e2028; border: 1px solid #3a3d48; border-radius: 4px;
                   padding: 10px; min-height: 120px; white-space: pre-wrap; font-size: 0.9rem;
                   overflow-y: auto; max-height: 400px; }

  .btn { background: #3b82f6; color: #fff; border: none; border-radius: 4px;
         padding: 8px 20px; font-size: 0.9rem; cursor: pointer; font-weight: 600; }
  .btn:hover { background: #2563eb; }
  .btn:disabled { background: #555; cursor: not-allowed; }
  .btn-row { margin-top: 10px; }

  .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid #555;
             border-top-color: #7eb8ff; border-radius: 50%; animation: spin 0.6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>

<h1>Hello from CITADEL</h1>

<!-- Status Card -->
<div class="card" id="status-card">
  <h2>System Status</h2>
  <div class="status-row">
    <span>PHP</span>
    <span class="badge ok">&#10003; running</span>
  </div>
  <div class="status-row" id="row-litellm">
    <span>LiteLLM</span>
    <span class="badge na" id="badge-litellm"><span class="spinner"></span> checking</span>
  </div>
  <div class="status-row" id="row-postgres" style="display:none">
    <span>PostgreSQL</span>
    <span class="badge na" id="badge-postgres"><span class="spinner"></span> checking</span>
  </div>
</div>

<!-- LLM Card -->
<div class="card" id="llm-card" style="display:none">
  <h2>LLM Chat</h2>
  <div class="llm-controls">
    <select id="sel-provider"><option value="">Provider...</option></select>
    <select id="sel-model"><option value="">Model...</option></select>
  </div>
  <div class="chat-area">
    <div>
      <textarea id="input-text" placeholder="Type your message..."></textarea>
      <div class="btn-row">
        <button class="btn" id="btn-send" disabled>Send</button>
      </div>
    </div>
    <div class="response-box" id="output-text">Response will appear here...</div>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);

// ── Status check ──────────────────────────────────────────────────────────

fetch('?api=status')
  .then(r => r.json())
  .then(s => {
    // LiteLLM
    const bLlm = $('#badge-litellm');
    if (s.litellm) {
      bLlm.className = 'badge ok';
      bLlm.innerHTML = '&#10003; connected';
      $('#llm-card').style.display = '';
      loadModels();
    } else {
      bLlm.className = 'badge na';
      bLlm.textContent = '— not configured';
    }

    // Postgres
    if (s.postgres_configured) {
      $('#row-postgres').style.display = '';
      const bPg = $('#badge-postgres');
      if (s.postgres_ok) {
        bPg.className = 'badge ok';
        bPg.innerHTML = '&#10003; ' + (s.postgres_version || 'connected');
      } else {
        bPg.className = 'badge fail';
        bPg.innerHTML = '&#10007; ' + (s.postgres_error || 'failed');
      }
    }
  })
  .catch(() => {
    $('#badge-litellm').className = 'badge fail';
    $('#badge-litellm').innerHTML = '&#10007; error';
  });

// ── LLM models ────────────────────────────────────────────────────────────

let allModels = [];

function loadModels() {
  fetch('?api=models')
    .then(r => r.json())
    .then(data => {
      const models = (data.data || []).map(m => m.id).sort();
      allModels = models;

      // Extract providers
      const providers = [...new Set(models.map(m => {
        const parts = m.split('/');
        return parts.length > 1 ? parts[0] : '(default)';
      }))].sort();

      const selP = $('#sel-provider');
      selP.innerHTML = '<option value="">All providers</option>';
      providers.forEach(p => {
        const o = document.createElement('option');
        o.value = p; o.textContent = p;
        selP.appendChild(o);
      });

      fillModels('');
    })
    .catch(e => {
      $('#badge-litellm').className = 'badge fail';
      $('#badge-litellm').innerHTML = '&#10007; models unreachable';
    });
}

function fillModels(provider) {
  const selM = $('#sel-model');
  const filtered = provider
    ? allModels.filter(m => m.startsWith(provider + '/') || (!m.includes('/') && provider === '(default)'))
    : allModels;

  selM.innerHTML = '<option value="">Select model...</option>';
  filtered.forEach(m => {
    const o = document.createElement('option');
    o.value = m;
    o.textContent = m.includes('/') ? m.split('/').slice(1).join('/') : m;
    selM.appendChild(o);
  });
  $('#btn-send').disabled = true;
}

$('#sel-provider').addEventListener('change', e => fillModels(e.target.value));
$('#sel-model').addEventListener('change', e => {
  $('#btn-send').disabled = !e.target.value;
});

// ── Chat ──────────────────────────────────────────────────────────────────

$('#btn-send').addEventListener('click', () => {
  const model = $('#sel-model').value;
  const text = $('#input-text').value.trim();
  if (!model || !text) return;

  const btn = $('#btn-send');
  const out = $('#output-text');
  btn.disabled = true;
  btn.textContent = 'Sending...';
  out.innerHTML = '<span class="spinner"></span> waiting for response...';

  fetch('?api=chat', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({model, text}),
  })
    .then(r => r.json())
    .then(data => {
      if (data.error) {
        out.textContent = 'Error: ' + data.error;
      } else {
        const msg = data.choices?.[0]?.message?.content || JSON.stringify(data);
        out.textContent = msg;
      }
    })
    .catch(e => { out.textContent = 'Error: ' + e.message; })
    .finally(() => { btn.disabled = false; btn.textContent = 'Send'; });
});

// Enter to send
$('#input-text').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    if (!$('#btn-send').disabled) $('#btn-send').click();
  }
});
</script>
</body>
</html>
