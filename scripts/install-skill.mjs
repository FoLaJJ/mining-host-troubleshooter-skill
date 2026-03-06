#!/usr/bin/env node
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SKILL_NAME = "mining-host-troubleshooter";
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const TARGETS = {
  codex: path.join(os.homedir(), ".codex", "skills"),
  agents: path.join(os.homedir(), ".agents", "skills"),
  "cc-switch": path.join(os.homedir(), ".cc-switch", "skills"),
};

function usage() {
  console.log(`Mining Host Troubleshooter skill installer

Usage:
  mining-host-troubleshooter-skill install [--target codex|agents|cc-switch|auto] [--dest DIR] [--name NAME] [--force]
  mining-host-troubleshooter-skill print-targets
  mining-host-troubleshooter-skill help

Examples:
  mining-host-troubleshooter-skill install --target codex
  mining-host-troubleshooter-skill install --target agents
  mining-host-troubleshooter-skill install --target cc-switch
  mining-host-troubleshooter-skill install --dest ~/custom-skills --name mining-host-troubleshooter
`);
}

function normalizeHome(p) {
  if (!p) {
    return p;
  }
  if (p === "~") {
    return os.homedir();
  }
  if (p.startsWith("~/") || p.startsWith("~\\")) {
    return path.join(os.homedir(), p.slice(2));
  }
  return p;
}

function parseArgs(argv) {
  const args = {
    cmd: argv[0] || "help",
    target: "auto",
    dest: "",
    name: SKILL_NAME,
    force: false,
  };
  for (let i = 1; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--target") {
      args.target = argv[i + 1] || "auto";
      i += 1;
    } else if (token === "--dest") {
      args.dest = normalizeHome(argv[i + 1] || "");
      i += 1;
    } else if (token === "--name") {
      args.name = argv[i + 1] || SKILL_NAME;
      i += 1;
    } else if (token === "--force") {
      args.force = true;
    } else if (token === "-h" || token === "--help") {
      args.cmd = "help";
    } else {
      throw new Error(`Unknown argument: ${token}`);
    }
  }
  return args;
}

async function exists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function resolveTargetRoot(target, dest) {
  if (dest) {
    return path.resolve(dest);
  }
  if (target !== "auto") {
    if (!TARGETS[target]) {
      throw new Error(`Unsupported target: ${target}`);
    }
    return TARGETS[target];
  }
  for (const key of ["codex", "agents", "cc-switch"]) {
    const root = TARGETS[key];
    if (await exists(root)) {
      return root;
    }
  }
  return TARGETS.codex;
}

function shouldSkip(sourcePath) {
  const rel = path.relative(PACKAGE_ROOT, sourcePath).replace(/\\/g, "/");
  if (!rel) {
    return false;
  }
  const blocked = [
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
  ];
  if (blocked.some((part) => rel === part || rel.startsWith(`${part}/`))) {
    return true;
  }
  if (rel.startsWith("reports/") && rel !== "reports/.gitkeep") {
    return true;
  }
  if (rel.endsWith(".pyc") || rel.endsWith(".pyo")) {
    return true;
  }
  return false;
}

async function copyTree(source, dest) {
  const stat = await fs.lstat(source);
  if (shouldSkip(source)) {
    return;
  }
  if (stat.isDirectory()) {
    await fs.mkdir(dest, { recursive: true });
    const entries = await fs.readdir(source, { withFileTypes: true });
    for (const entry of entries) {
      await copyTree(path.join(source, entry.name), path.join(dest, entry.name));
    }
    return;
  }
  await fs.mkdir(path.dirname(dest), { recursive: true });
  await fs.copyFile(source, dest);
}

async function install(args) {
  const root = await resolveTargetRoot(args.target, args.dest);
  const finalDir = path.join(root, args.name);
  await fs.mkdir(root, { recursive: true });
  if (await exists(finalDir)) {
    if (!args.force) {
      throw new Error(`Target already exists: ${finalDir}. Use --force to replace it.`);
    }
    await fs.rm(finalDir, { recursive: true, force: true });
  }
  await copyTree(PACKAGE_ROOT, finalDir);
  console.log(`Installed ${SKILL_NAME} to ${finalDir}`);
  console.log(`Target root: ${root}`);
}

async function printTargets() {
  for (const [name, root] of Object.entries(TARGETS)) {
    console.log(`${name}: ${root}`);
  }
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(String(error.message || error));
    usage();
    process.exit(2);
  }

  if (args.cmd === "help") {
    usage();
    return;
  }
  if (args.cmd === "print-targets") {
    await printTargets();
    return;
  }
  if (args.cmd === "install") {
    await install(args);
    return;
  }

  console.error(`Unsupported command: ${args.cmd}`);
  usage();
  process.exit(2);
}

main().catch((error) => {
  console.error(String(error.message || error));
  process.exit(1);
});
