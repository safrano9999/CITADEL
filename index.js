import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const pluginRoot = path.resolve(fileURLToPath(new URL(".", import.meta.url)));
const defaultServicesPath = path.join(pluginRoot, "services.json");
const defaultScanScript = path.join(pluginRoot, "scan.sh");
const providerNames = new Set(["localhost", "subnet", "tailscale", "cloudflare", "other"]);
let activeScan;

const configSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    servicesPath: {
      type: "string",
      description: "Optional path to the CITADEL services.json file.",
    },
    scanScript: {
      type: "string",
      description: "Optional path to the CITADEL scan.sh script.",
    },
  },
};

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function pluginConfig(ctx) {
  if (isRecord(ctx?.pluginConfig)) {
    return ctx.pluginConfig;
  }
  const config = ctx?.getRuntimeConfig?.() ?? ctx?.runtimeConfig ?? ctx?.config;
  const entry = isRecord(config?.plugins?.entries?.citadel)
    ? config.plugins.entries.citadel
    : undefined;
  return isRecord(entry?.config) ? entry.config : {};
}

function resolveConfiguredPath(ctx, key, fallback) {
  const configured = readString(pluginConfig(ctx)[key]);
  if (!configured) {
    return fallback;
  }
  if (configured.startsWith("~/")) {
    return path.join(process.env.HOME ?? process.cwd(), configured.slice(2));
  }
  return path.resolve(pluginRoot, configured);
}

function readServices(ctx) {
  const servicesPath = resolveConfiguredPath(ctx, "servicesPath", defaultServicesPath);
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(servicesPath, "utf8"));
  } catch (error) {
    throw new Error(`CITADEL services unavailable: ${error.message}`);
  }
  return {
    generatedAt: readString(parsed.generated_at),
    services: Array.isArray(parsed.http_services) ? parsed.http_services : [],
    otherPorts: Array.isArray(parsed.other_ports) ? parsed.other_ports : [],
  };
}

function commandButton(label, command, style) {
  return {
    label,
    action: { type: "command", command },
    reusable: true,
    ...(style ? { style } : {}),
  };
}

function navigationBlocks(activeProvider) {
  const providers = ["localhost", "subnet", "tailscale", "cloudflare", "other"];
  return [
    {
      type: "buttons",
      buttons: providers.map((provider) => commandButton(
        provider[0].toUpperCase() + provider.slice(1),
        `/citadel ${provider}`,
        provider === activeProvider ? "primary" : "secondary",
      )),
    },
    {
      type: "buttons",
      buttons: [commandButton("Scan", "/citadel scan", "success")],
    },
  ];
}

function serviceLabel(service) {
  const name = readString(service.name) ?? readString(service.title) ?? "Service";
  const port = Number.isInteger(service.port) ? ` :${service.port}` : "";
  return `${name}${port}`;
}

function createProviderReply(data, provider) {
  if (provider === "other") {
    const lines = data.otherPorts.map((item) => {
      const port = Number.isInteger(item?.port) ? `:${item.port}` : ":?";
      const details = [readString(item?.service), readString(item?.process), readString(item?.addr)]
        .filter(Boolean)
        .join(" | ");
      return details ? `${port} - ${details}` : port;
    });
    return {
      text: ["CITADEL - Other", ...(lines.length ? lines : ["No other listening ports."])].join("\n"),
      presentation: { tone: "neutral", blocks: navigationBlocks(provider) },
    };
  }

  const services = data.services
    .map((service) => ({ service, url: readString(service?.urls?.[provider]) }))
    .filter((entry) => entry.url);
  const lines = services.map(({ service, url }) => `${serviceLabel(service)}\n${url}`);
  const serviceBlocks = services.map(({ service, url }) => ({
    type: "buttons",
    buttons: [{ label: serviceLabel(service), url }],
  }));
  return {
    text: [
      `CITADEL - ${provider[0].toUpperCase() + provider.slice(1)}`,
      ...(lines.length ? lines : ["No routes available."]),
    ].join("\n\n"),
    presentation: {
      tone: "neutral",
      blocks: [...serviceBlocks, ...navigationBlocks(provider)],
    },
  };
}

function runScanProcess(script) {
  return new Promise((resolve, reject) => {
    const child = spawn("/bin/bash", [script], {
      cwd: path.dirname(script),
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error("CITADEL scan timed out."));
    }, 600_000);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code === 0) {
        resolve(stdout.trim());
        return;
      }
      reject(new Error((stderr || stdout).trim() || `CITADEL scan exited with ${code}`));
    });
  });
}

async function runScan(ctx) {
  if (!activeScan) {
    const script = resolveConfiguredPath(ctx, "scanScript", defaultScanScript);
    activeScan = runScanProcess(script).finally(() => {
      activeScan = undefined;
    });
  }
  return activeScan;
}

async function handleCommand(ctx, api) {
  const raw = readString(ctx.args)?.toLowerCase() ?? "localhost";
  const [action, providerArg] = raw.split(/\s+/, 2);
  if (action === "scan") {
    await runScan(api);
    const provider = providerNames.has(providerArg) ? providerArg : "localhost";
    const reply = createProviderReply(readServices(api), provider);
    reply.text = `CITADEL scan completed.\n\n${reply.text}`;
    return reply;
  }
  if (!providerNames.has(action)) {
    return { text: "Usage: /citadel [localhost|subnet|tailscale|cloudflare|other|scan]" };
  }
  return createProviderReply(readServices(api), action);
}

export default definePluginEntry({
  id: "citadel",
  name: "CITADEL",
  description: "Lists CITADEL routes and runs deterministic service scans.",
  configSchema,
  register(api) {
    api.registerCommand({
      name: "citadel",
      description: "List CITADEL routes or scan listening services.",
      acceptsArgs: true,
      requireAuth: true,
      handler: (ctx) => handleCommand(ctx, api),
    });
  },
});
