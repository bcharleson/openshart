# OpenShart OpenClaw Installation

OpenClaw resolves plugins from `plugins.load.paths` using these rules:

1. Reads the directory `package.json`.
2. If `package["openclaw"].extensions` exists, it resolves entries from package root.
3. Without it, it falls back to root `index.{ts,js,mjs,cjs}`.
4. If still nothing, it scans raw extension files and looks for manifests under subfolders.

`package["openclaw"].extensions` must be present, otherwise the manifest lookup happens in the wrong directory.

## Required files

At repository root:

- `package.json` (must include `"openclaw": { "extensions": ["./dist/openclaw-plugin.js"] }`)
- `openclaw.plugin.json`
- `dist/openclaw-plugin.js` (from `npm run build`)

## Install commands

```bash
OC="cd /Users/<user>/openclaw && node openclaw.mjs"
PLUGIN_PATH="/Users/<user>/openclaw-plugin-openshart"

$OC config set plugins.load.paths.[0] "$PLUGIN_PATH"
$OC config set plugins.entries.openshart.enabled true
$OC config set plugins.entries.openshart.config.securityLevel "enterprise"
$OC config set plugins.entries.openshart.config.storagePath "/Users/<user>/.openclaw/openshart"
$OC config set plugins.entries.openshart.config.useSQLite true
$OC config set plugins.entries.openshart.config.encryptionKey "<hex-or-base64-key>"
$OC config set plugins.slots.memory "openshart"
```

If `useSQLite` is `true` (or `storagePath` is set), the plugin requires a 32-byte key via `config.encryptionKey` or `OPENSHART_ENCRYPTION_KEY`.

## What to avoid (and why)

- Missing `openclaw.extensions` under `openclaw`: OpenClaw scans subdirectories and looks for `openclaw.plugin.json` in `src/` or `dist/`.
- Manifest in `dist/`: only needed for rootless extension folders; keep it at package root when using `openclaw.extensions`.
- `ChainVerificationResult` mismatch:
  - Actual shape: `{ valid, entriesChecked, firstInvalidIndex, error? }`
  - Not: `{ entries, brokenAt }`
- `cp -R` over existing path:
  - Prefer `rm -rf` target first, then copy.
