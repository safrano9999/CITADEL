<?php
$ini_path = __DIR__ . '/config.ini';
$ini_all = is_file($ini_path) ? parse_ini_file($ini_path, true) : [];
$ini = (is_array($ini_all) && isset($ini_all['CITADEL']) && is_array($ini_all['CITADEL']))
    ? $ini_all['CITADEL']
    : [];

return [
    'cache_dir' => __DIR__ . '/cache',
    'icons_dir' => __DIR__ . '/icons',
    'services_file' => __DIR__ . '/services.json',
    'tailscale_file' => __DIR__ . '/tailscale.json',
    'extensions_enabled_dir' => __DIR__ . '/extensions/enabled',
    'extensions_disabled_dir' => __DIR__ . '/extensions/disabled',
    'providers_state_file' => __DIR__ . '/extensions/providers_state.json',
    'ui_config_file' => __DIR__ . '/extensions/ui.json',
];
