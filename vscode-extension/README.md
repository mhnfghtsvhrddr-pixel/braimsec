# BraimSec Scanner for VS Code

Scan your code with the BraimSec security engine — SAST, leaked secrets and
IaC misconfigurations — right inside VS Code.

## Setup

1. Install the extension (see `PUBLISHING.md` for the Marketplace status).
2. Run **BraimSec: Set Server URL** and enter your BraimSec server URL,
   e.g. `https://api.braimsec.world`.
3. Run **BraimSec: Set API Key** and paste your API key. The key is stored in
   VS Code's SecretStorage — it is never written to `settings.json` and is
   only ever sent to your configured server.

## Commands

| Command | What it does |
|---|---|
| `BraimSec: Scan Workspace` | Zips the open workspace (minus `node_modules`, `.git`, …), uploads it to your BraimSec server, waits for the scan, then shows findings. |
| `BraimSec: Scan Current File` | Same, but only the file open in the editor. |
| `BraimSec: Set API Key` | Store the API key securely. |
| `BraimSec: Set Server URL` | Point at your BraimSec server. |
| `BraimSec: Clear Results` | Clear the findings view and editor squiggles. |

## Results

- A **BraimSec** activity-bar view lists findings grouped by severity
  (Critical / Warning / Note). Click a finding to jump to the file and line.
- Offending lines are also underlined in the editor (Problems panel).
- The status bar shows scan progress and the final finding count.

## Settings

- `braimsec.serverUrl` — your BraimSec server URL.
- `braimsec.projectId` — optional: file scans under a project.
- `braimsec.pollIntervalMs` — how often to poll while a scan runs (default 3000).

## Privacy

The extension sends your code **only** to the BraimSec server URL you
configured, and only when you explicitly run a scan command. No telemetry,
no bundled secrets.

## Development

```sh
npm install
npm run compile   # type-check + build to out/
npm test          # compile + unit tests (node:test, no VS Code needed)
```
