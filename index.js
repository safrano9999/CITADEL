import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const pluginRoot = path.resolve(fileURLToPath(new URL(".", import.meta.url)));
const dataRoot = process.env.CITADEL_DATA_DIR
  ? path.resolve(process.env.CITADEL_DATA_DIR)
  : pluginRoot;
const defaultServicesPath = path.join(pluginRoot, "services.json");
const defaultPolicyPath = path.join(dataRoot, "ports.filter.json");
const defaultScanScript = path.join(pluginRoot, "scan.sh");
const coreBridge = path.join(pluginRoot, "functions", "plugin_bridge.py");
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
    policyPath: {
      type: "string",
      description: "Optional path to the CITADEL ports.filter.json file.",
    },
    scanScript: {
      type: "string",
      description: "Optional path to the CITADEL scan.sh script.",
    },
    pythonPath: {
      type: "string",
      description: "Optional Python executable used by the CITADEL core bridge.",
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

function runCoreProcess(ctx, operation, args = [], input) {
  const cfg = pluginConfig(ctx);
  const python = readString(cfg.pythonPath) ?? readString(process.env.CITADEL_PYTHON) ?? "python3";
  const servicesPath = resolveConfiguredPath(ctx, "servicesPath", defaultServicesPath);
  const policyPath = resolveConfiguredPath(ctx, "policyPath", defaultPolicyPath);
  const pythonPath = [path.join(pluginRoot, "functions"), pluginRoot, process.env.PYTHONPATH]
    .filter(Boolean)
    .join(path.delimiter);

  return new Promise((resolve, reject) => {
    const child = spawn(
      python,
      [
        coreBridge,
        "--services-path",
        servicesPath,
        "--policy-path",
        policyPath,
        operation,
        ...args,
      ],
      {
        cwd: pluginRoot,
        env: { ...process.env, PYTHONPATH: pythonPath, PYTHONUNBUFFERED: "1" },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (callback) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      callback();
    };
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      finish(() => reject(new Error("CITADEL core operation timed out.")));
    }, 30_000);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.once("error", (error) => {
      finish(() => reject(error));
    });
    child.once("close", (code) => {
      finish(() => {
        if (code !== 0) {
          reject(new Error(stderr.trim() || stdout.trim() || `CITADEL core exited with ${code}`));
          return;
        }
        try {
          resolve(JSON.parse(stdout));
        } catch (error) {
          reject(new Error(`CITADEL core returned invalid JSON: ${error.message}`));
        }
      });
    });
    if (input === undefined) {
      child.stdin.end();
    } else {
      child.stdin.end(JSON.stringify(input));
    }
  });
}

function readDashboard(ctx) {
  return runCoreProcess(ctx, "dashboard");
}

function saveCloudflareRule(ctx, port, rule) {
  return runCoreProcess(ctx, "save-cloudflare-rule", [String(port)], rule);
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
  const blocks = [
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
      buttons: [commandButton("Scan", `/citadel scan ${activeProvider}`, "success")],
    },
  ];
  if (activeProvider === "cloudflare") {
    blocks.push({
      type: "buttons",
      buttons: [commandButton("EDIT", "/citadel cloudflare edit", "primary")],
    });
  }
  return blocks;
}

function serviceLabel(service) {
  const name = readString(service.display_name)
    ?? readString(service.name)
    ?? readString(service.title)
    ?? "Service";
  const port = Number.isInteger(service.port) ? ` :${service.port}` : "";
  return `${name}${port}`;
}

function serviceEntries(data, provider) {
  return (data.http_tiles ?? [])
    .map((service) => ({
      service,
      url: readString(service?.provider_urls?.[provider]) ?? readString(service?.urls?.[provider]),
    }))
    .filter((entry) => entry.url);
}

function createOtherReply(data, selectedPort) {
  if (selectedPort) {
    const selected = (data.other_ports ?? []).find((item) => Number(item?.port) === selectedPort);
    if (!selected) {
      return { text: `CITADEL - Other :${selectedPort}\nPort not found.` };
    }
    const details = [readString(selected.service), readString(selected.process), readString(selected.addr)]
      .filter(Boolean)
      .join(" | ");
    return {
      text: `CITADEL - Other :${selectedPort}${details ? `\n${details}` : ""}`,
      presentation: { tone: "neutral", blocks: navigationBlocks("other") },
    };
  }

  const portBlocks = (data.other_ports ?? []).map((item) => {
    const port = Number(item?.port);
    const label = Number.isInteger(port)
      ? `:${port}${readString(item?.service) ? ` ${item.service}` : ""}`
      : "Unknown port";
    return {
      type: "buttons",
      buttons: [commandButton(label, `/citadel other ${port}`)],
    };
  });
  return {
    text: "CITADEL - Other",
    presentation: {
      tone: "neutral",
      blocks: [...portBlocks, ...navigationBlocks("other")],
    },
  };
}

function createProviderReply(data, provider) {
  if (provider === "other") {
    return createOtherReply(data);
  }

  const serviceBlocks = serviceEntries(data, provider).map(({ service, url }) => ({
    type: "buttons",
    buttons: [{ label: serviceLabel(service), url, priority: service.featured ? 100 : 0 }],
  }));
  return {
    text: `CITADEL - ${provider[0].toUpperCase() + provider.slice(1)}`,
    presentation: {
      tone: "neutral",
      blocks: [...serviceBlocks, ...navigationBlocks(provider)],
    },
  };
}

function findCloudflareTile(data, rawPort) {
  const port = Number(rawPort);
  if (!Number.isInteger(port)) {
    return undefined;
  }
  return (data.http_tiles ?? []).find((service) => service.port === port);
}

function cloudflareEditListReply(data) {
  const serviceBlocks = (data.http_tiles ?? []).map((service) => ({
    type: "buttons",
    buttons: [commandButton(serviceLabel(service), `/citadel cloudflare edit ${service.port}`)],
  }));
  return {
    text: "CITADEL - Cloudflare Edit",
    presentation: {
      tone: "neutral",
      blocks: [
        ...serviceBlocks,
        {
          type: "buttons",
          buttons: [commandButton("Back", "/citadel cloudflare", "secondary")],
        },
      ],
    },
  };
}

function cloudflareRuleReply(data, service, status) {
  const port = service.port;
  const rule = service.cloudflare_rule ?? {
    subdomains: [String(port)],
    whitelist: false,
    emails: [],
  };
  const controls = [
    {
      type: "buttons",
      buttons: [commandButton(
        rule.whitelist ? "Whitelist ON" : "Whitelist OFF",
        `/citadel cloudflare whitelist ${port} ${rule.whitelist ? "off" : "on"}`,
        rule.whitelist ? "success" : "danger",
      )],
    },
  ];

  for (const email of rule.emails ?? []) {
    controls.push({
      type: "buttons",
      buttons: [commandButton(
        `Remove ${email}`,
        `/citadel cloudflare remove-email ${port} ${email}`,
        "danger",
      )],
    });
  }
  for (const email of data.cloudflare_default_emails ?? []) {
    if (!(rule.emails ?? []).includes(email)) {
      controls.push({
        type: "buttons",
        buttons: [commandButton(
          `Use ${email}`,
          `/citadel cloudflare email ${port} ${email}`,
          "primary",
        )],
      });
    }
  }
  controls.push(
    {
      type: "buttons",
      buttons: [commandButton("Set email", `/citadel cloudflare email ${port}`, "primary")],
    },
    {
      type: "buttons",
      buttons: [
        commandButton("Back", "/citadel cloudflare edit", "secondary"),
        commandButton("Save & Scan", `/citadel cloudflare apply ${port}`, "success"),
      ],
    },
  );

  return {
    text: [
      "CITADEL - Cloudflare Edit",
      serviceLabel(service),
      status === "saved" ? "Changed. Select Save & Scan to apply. Wait for ✅ to confirm." : undefined,
      status === "applied" ? "✅ Applied." : undefined,
    ].filter(Boolean).join("\n"),
    presentation: { tone: status ? "success" : "neutral", blocks: controls },
  };
}

function emailPromptReply(data, service) {
  const port = service.port;
  const reply = cloudflareRuleReply(data, service);
  reply.text = [
    "CITADEL - Cloudflare Edit",
    serviceLabel(service),
    `Send: /citadel cloudflare email ${port} name@example.com`,
  ].join("\n");
  return reply;
}

async function saveAndRenderCloudflareRule(api, port, rule) {
  await saveCloudflareRule(api, port, rule);
  const refreshed = await readDashboard(api);
  const service = findCloudflareTile(refreshed, port);
  if (!service) {
    throw new Error(`CITADEL service on port ${port} disappeared after saving.`);
  }
  return cloudflareRuleReply(refreshed, service, "saved");
}

async function saveScanAndRenderCloudflareRule(api, port, rule) {
  await saveCloudflareRule(api, port, rule);
  await runScan(api);
  const refreshed = await readDashboard(api);
  const service = findCloudflareTile(refreshed, port);
  if (!service) {
    throw new Error(`CITADEL service on port ${port} disappeared after scanning.`);
  }
  return cloudflareRuleReply(refreshed, service, "applied");
}

async function handleCloudflareCommand(args, data, api) {
  const operation = args[0]?.toLowerCase();
  if (!operation) {
    return createProviderReply(data, "cloudflare");
  }
  if (operation === "edit") {
    if (!args[1]) {
      return cloudflareEditListReply(data);
    }
    const service = findCloudflareTile(data, args[1]);
    return service
      ? cloudflareRuleReply(data, service)
      : { text: `CITADEL - Cloudflare Edit\nUnknown service port: ${args[1]}` };
  }

  const service = findCloudflareTile(data, args[1]);
  if (!service) {
    return { text: `CITADEL - Cloudflare Edit\nUnknown service port: ${args[1] ?? ""}` };
  }
  const port = service.port;
  const rule = {
    subdomains: [...(service.cloudflare_rule?.subdomains ?? [String(port)])],
    whitelist: Boolean(service.cloudflare_rule?.whitelist),
    emails: [...(service.cloudflare_rule?.emails ?? [])],
  };

  if (operation === "apply") {
    return saveScanAndRenderCloudflareRule(api, port, rule);
  }

  if (operation === "whitelist") {
    const enabled = args[2]?.toLowerCase() === "on";
    rule.whitelist = enabled;
    if (!enabled) {
      rule.emails = [];
    } else if (rule.emails.length === 0) {
      rule.emails = [...(data.cloudflare_default_emails ?? [])];
      if (rule.emails.length === 0) {
        return emailPromptReply(data, service);
      }
    }
    return saveAndRenderCloudflareRule(api, port, rule);
  }

  if (operation === "email") {
    const emails = args.slice(2)
      .join(" ")
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);
    if (emails.length === 0) {
      return emailPromptReply(data, service);
    }
    rule.whitelist = true;
    rule.emails = emails;
    return saveAndRenderCloudflareRule(api, port, rule);
  }

  if (operation === "remove-email") {
    const email = args.slice(2).join(" ").trim().toLowerCase();
    rule.emails = rule.emails.filter((value) => value !== email);
    if (rule.emails.length === 0) {
      rule.whitelist = false;
    }
    return saveAndRenderCloudflareRule(api, port, rule);
  }

  return { text: "Usage: /citadel cloudflare [edit|whitelist|email|remove-email|apply]" };
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
  const raw = readString(ctx.args) ?? "localhost";
  const parts = raw.split(/\s+/);
  const action = parts[0].toLowerCase();

  if (action === "scan") {
    await runScan(api);
    const provider = providerNames.has(parts[1]?.toLowerCase())
      ? parts[1].toLowerCase()
      : "localhost";
    const reply = createProviderReply(await readDashboard(api), provider);
    reply.text = `CITADEL scan completed - ${provider[0].toUpperCase() + provider.slice(1)}`;
    return reply;
  }

  const data = await readDashboard(api);
  if (action === "cloudflare") {
    return handleCloudflareCommand(parts.slice(1), data, api);
  }
  if (action === "other" && parts[1]) {
    return createOtherReply(data, Number(parts[1]));
  }
  if (!providerNames.has(action)) {
    return {
      text: "Usage: /citadel [localhost|subnet|tailscale|cloudflare|other|scan]",
    };
  }
  return createProviderReply(data, action);
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
