<?php
$cfg = require __DIR__ . '/config.php';

$services_file = $cfg['services_file'];
$enabled_dir = $cfg['extensions_enabled_dir'];
$providers_state_file = $cfg['providers_state_file'];
$ui_config_file = $cfg['ui_config_file'] ?? (__DIR__ . '/extensions/ui.json');

function read_json_file(string $path, array $fallback = []): array {
    if (!is_file($path)) {
        return $fallback;
    }
    $decoded = json_decode(file_get_contents($path), true);
    return is_array($decoded) ? $decoded : $fallback;
}

$services_payload = read_json_file($services_file, [
    'http_services' => [],
    'other_ports' => [],
]);

$providers_state = read_json_file($providers_state_file, [
    'considered_providers' => [],
    'available_providers' => [],
    'errors' => [],
]);

$ui_cfg = read_json_file($ui_config_file, [
    'default_provider' => 'localhost',
    'default_refresh_seconds' => 0,
]);

$http_tiles = is_array($services_payload['http_services'] ?? null) ? $services_payload['http_services'] : [];
$other_ports = is_array($services_payload['other_ports'] ?? null) ? $services_payload['other_ports'] : [];

$alerts = [];
$provider_options = [];
$provider_urls_by_port = [];
$provider_header_meta = [];

$state_errors = is_array($providers_state['errors'] ?? null) ? $providers_state['errors'] : [];
foreach ($state_errors as $err) {
    if (is_string($err) && $err !== '') {
        $alerts[] = '[dispatch] ' . $err;
    }
}

$enabled_provider_dirs = [];
if (is_dir($enabled_dir)) {
    foreach (scandir($enabled_dir) as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $full = $enabled_dir . '/' . $entry;
        if (is_dir($full)) {
            $enabled_provider_dirs[] = $full;
        }
    }
}

if (!$enabled_provider_dirs) {
    $alerts[] = 'Keine Extension in extensions/enabled gefunden. Bitte mindestens localhost/subnet/tailscale aktivieren.';
}

$considered = array_map('strval', $providers_state['considered_providers'] ?? []);
$available = array_map('strval', $providers_state['available_providers'] ?? []);

foreach ($enabled_provider_dirs as $provider_dir) {
    $provider_id = basename($provider_dir);

    $ext = read_json_file($provider_dir . '/extension.json', []);
    $routes = read_json_file($provider_dir . '/routes.json', []);

    $label = (string)($routes['label'] ?? ($ext['label'] ?? ucfirst($provider_id)));

    $is_considered = (bool)($routes['considered'] ?? in_array($provider_id, $considered, true));
    $is_available = (bool)($routes['available'] ?? in_array($provider_id, $available, true));

    $header_value = '';
    if ($provider_id === 'localhost') {
        $header_value = '127.0.0.1';
    } elseif ($provider_id === 'subnet') {
        $header_value = (string)($routes['subnet_ip'] ?? '');
    } elseif ($provider_id === 'tailscale') {
        $header_value = (string)($routes['domain'] ?? '');
    }

    if ($is_considered && $header_value !== '') {
        $provider_header_meta[] = [
            'label' => $label,
            'value' => $header_value,
        ];
    }

    if ($is_considered) {
        $provider_options[$provider_id] = $label;
    }

    $svc_routes = $routes['services'] ?? [];
    if (is_array($svc_routes)) {
        foreach ($svc_routes as $port => $url) {
            if (!is_string($url) || $url === '') {
                continue;
            }
            $provider_urls_by_port[$provider_id][(string)$port] = $url;
        }
    }

    if (($routes['errors'] ?? false) && is_array($routes['errors'])) {
        foreach ($routes['errors'] as $err) {
            if ($err) {
                $alerts[] = '[' . $provider_id . '] ' . $err;
            }
        }
    }

    if ($is_considered && !$is_available) {
        $alerts[] = '[' . $provider_id . '] beim letzten Scan berücksichtigt, aber ohne aktive Routen.';
    }
}

if (!$provider_options) {
    $alerts[] = 'Keine Provider aus extensions/enabled wurden im letzten Scan berücksichtigt.';
}

$configured_default_mode = (string)($ui_cfg['default_provider'] ?? 'localhost');
$default_mode = $configured_default_mode;
if (!array_key_exists($default_mode, $provider_options)) {
    $default_mode = array_key_first($provider_options) ?: 'localhost';
}
$default_refresh_seconds = (int)($ui_cfg['default_refresh_seconds'] ?? 0);
$provider_order = array_keys($provider_options);

$ts_file = __DIR__ . '/last_scan.txt';
$last_scan = is_file($ts_file) ? trim(file_get_contents($ts_file)) : null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CITADEL</title>
<link rel="icon" type="image/svg+xml" href="citadel.svg">
<link rel="stylesheet" href="assets/style.css">
</head>
<body
    data-default-mode="<?= htmlspecialchars($default_mode) ?>"
    data-default-refresh="<?= (int)$default_refresh_seconds ?>"
>

<header class="site-header">
    <div class="brand">
        <img src="citadel.svg" alt="CITADEL">
        <h1>CITADEL</h1>
    </div>
    <?php if ($provider_header_meta): ?>
        <?php foreach ($provider_header_meta as $meta): ?>
            <span class="header-meta"><?= htmlspecialchars($meta['label'] . ': ' . $meta['value']) ?></span>
        <?php endforeach; ?>
    <?php endif; ?>
    <?php if ($last_scan): ?>
    <span class="header-meta">last scan <?= htmlspecialchars($last_scan) ?></span>
    <?php endif; ?>

    <div class="header-controls">
        <label class="control" for="route-mode-sel">
            <span>Provider</span>
            <select id="route-mode-sel" <?= $provider_options ? '' : 'disabled' ?>>
                <?php foreach ($provider_options as $mode => $label): ?>
                <option value="<?= htmlspecialchars($mode) ?>"><?= htmlspecialchars($label) ?></option>
                <?php endforeach; ?>
            </select>
            <button id="save-default-btn" class="btn-default" type="button" <?= $provider_options ? '' : 'disabled' ?>>
                Save as default
            </button>
            <small id="mode-default-hint">Saved default: -</small>
        </label>

        <label class="control" for="refresh-sel">
            <span>Refresh</span>
            <select id="refresh-sel">
                <option value="0">off</option>
                <option value="60">1 min</option>
                <option value="120">2 min</option>
                <option value="300">5 min</option>
                <option value="600">10 min</option>
                <option value="1800">30 min</option>
                <option value="3600">1h</option>
                <option value="21600">6h</option>
                <option value="43200">12h</option>
                <option value="86400">24h</option>
            </select>
            <small>page reload</small>
        </label>
    </div>
</header>

<main class="layout">
    <?php if ($alerts): ?>
    <section class="alerts">
        <?php foreach ($alerts as $msg): ?>
        <div class="alert"><?= htmlspecialchars($msg) ?></div>
        <?php endforeach; ?>
    </section>
    <?php endif; ?>

    <?php if ($http_tiles): ?>
    <div class="section-title">Services</div>
    <section class="grid" id="services-grid">
        <?php foreach ($http_tiles as $svc):
            $port = (string)(int)($svc['port'] ?? 0);
            $scheme = (string)($svc['scheme'] ?? 'http');
        ?>
        <article class="tile" tabindex="0"
            <?php foreach ($provider_order as $pid):
                $url = (string)($provider_urls_by_port[$pid][$port] ?? ($svc['urls'][$pid] ?? ''));
            ?>
            data-url-<?= htmlspecialchars($pid) ?>="<?= htmlspecialchars($url) ?>"
            <?php endforeach; ?>
        >
            <?php if (!empty($svc['icon'])): ?>
                <img class="tile-icon" src="<?= htmlspecialchars((string)$svc['icon']) ?>" alt="<?= htmlspecialchars((string)($svc['name'] ?? 'Service')) ?>">
            <?php else: ?>
                <div class="tile-icon-placeholder">🏠</div>
            <?php endif; ?>

            <span class="tile-name"><?= htmlspecialchars((string)($svc['name'] ?? ('Port ' . $port))) ?></span>
            <span class="tile-port"><?= $scheme === 'https' ? '🔒 ' : '' ?>:<?= htmlspecialchars($port) ?></span>
            <span class="tile-url">-</span>
        </article>
        <?php endforeach; ?>
    </section>
    <?php endif; ?>

    <?php if ($other_ports): ?>
    <div class="section-title">Other Listening Ports</div>
    <section class="other-wrap">
        <table class="other-table">
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Address</th>
                    <th>Process</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($other_ports as $p): ?>
                <tr>
                    <td>:<?= (int)($p['port'] ?? 0) ?></td>
                    <td><?= htmlspecialchars((string)($p['service'] ?? '—')) ?></td>
                    <td><?= htmlspecialchars((string)($p['addr'] ?? '*')) ?></td>
                    <td><?= htmlspecialchars((string)($p['process'] ?? '—')) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </section>
    <?php endif; ?>
</main>

<script>
const modeSel = document.getElementById('route-mode-sel');
const saveDefaultBtn = document.getElementById('save-default-btn');
const modeDefaultHint = document.getElementById('mode-default-hint');
const refreshSel = document.getElementById('refresh-sel');
const tiles = Array.from(document.querySelectorAll('.tile'));
const defaultMode = document.body.dataset.defaultMode || 'localhost';
const defaultRefresh = parseInt(document.body.dataset.defaultRefresh || '0', 10) || 0;
const providerOrder = <?= json_encode($provider_order, JSON_UNESCAPED_SLASHES) ?>;
const routeDefaultKey = 'citadel-route-default';

function getTileUrl(tile, mode) {
  return tile.getAttribute(`data-url-${mode}`) || '';
}

function chooseTileUrl(tile, preferredMode) {
  const preferred = getTileUrl(tile, preferredMode);
  if (preferred) {
    return { url: preferred, fallback: false };
  }

  for (const mode of providerOrder) {
    const candidate = getTileUrl(tile, mode);
    if (candidate) {
      return { url: candidate, fallback: true };
    }
  }

  return { url: '', fallback: false };
}

function compactUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.host + parsed.pathname;
  } catch {
    return url;
  }
}

function applyMode(mode) {
  tiles.forEach(tile => {
    const desired = getTileUrl(tile, mode);
    const choice = chooseTileUrl(tile, mode);

    tile.dataset.activeUrl = choice.url;
    tile.classList.toggle('no-link', !choice.url);
    tile.classList.toggle('mode-fallback', Boolean(choice.url && !desired));

    const label = tile.querySelector('.tile-url');
    if (!choice.url) {
      label.textContent = 'no route available';
    } else if (choice.fallback) {
      label.textContent = 'fallback: ' + compactUrl(choice.url);
    } else {
      label.textContent = compactUrl(choice.url);
    }
  });
}

function renderModeDefaultHint(mode) {
  if (!modeDefaultHint) {
    return;
  }
  const option = modeSel ? modeSel.querySelector(`option[value="${mode}"]`) : null;
  if (!option) {
    modeDefaultHint.textContent = 'Saved default: -';
    return;
  }
  modeDefaultHint.textContent = `Saved default: ${option.textContent}`;
}

function openTile(tile) {
  const url = tile.dataset.activeUrl || '';
  if (!url) {
    return;
  }
  window.open(url, '_blank', 'noopener');
}

tiles.forEach(tile => {
  tile.addEventListener('click', () => openTile(tile));
  tile.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' || ev.key === ' ') {
      ev.preventDefault();
      openTile(tile);
    }
  });
});

if (modeSel && modeSel.options.length > 0) {
  const storedMode = localStorage.getItem(routeDefaultKey);
  const knownModes = Array.from(modeSel.options).map(o => o.value);
  modeSel.value = knownModes.includes(storedMode) ? storedMode : defaultMode;
  applyMode(modeSel.value);
  renderModeDefaultHint(knownModes.includes(storedMode) ? storedMode : defaultMode);

  modeSel.addEventListener('change', () => {
    applyMode(modeSel.value);
  });

  if (saveDefaultBtn) {
    saveDefaultBtn.addEventListener('click', () => {
      localStorage.setItem(routeDefaultKey, modeSel.value);
      renderModeDefaultHint(modeSel.value);
    });
  }
} else {
  applyMode(defaultMode);
  renderModeDefaultHint('');
}

let refreshTimer = null;
function applyRefresh(seconds) {
  clearInterval(refreshTimer);
  if (seconds > 0) {
    refreshTimer = setInterval(() => location.reload(), seconds * 1000);
  }
}

const storedRefresh = localStorage.getItem('citadel-refresh');
refreshSel.value = storedRefresh !== null ? storedRefresh : String(defaultRefresh);
if (!Array.from(refreshSel.options).some(o => o.value === refreshSel.value)) {
  refreshSel.value = '0';
}
applyRefresh(parseInt(refreshSel.value, 10));

refreshSel.addEventListener('change', () => {
  localStorage.setItem('citadel-refresh', refreshSel.value);
  applyRefresh(parseInt(refreshSel.value, 10));
});
</script>
</body>
</html>
