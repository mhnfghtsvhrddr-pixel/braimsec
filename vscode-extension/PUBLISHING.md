# Publishing `braimsec-scanner` — honest status

**Status: NOT published.** This folder contains a complete, compiling
extension, but publishing to the VS Code Marketplace (or Open VSX) is a
manual step that needs the publisher's Microsoft account. Nothing here
claims the extension is live — do not tell users it is.

## What is ready

- `npm install && npm run compile` — clean TypeScript build.
- `npm test` — 9 unit tests green (API client against a mock HTTP server,
  zip helpers).
- `package.json` — extension id `braimsec-scanner`, commands, views,
  configuration; icon at `images/shield.png`.
- No secrets bundled; the API key lives in SecretStorage at runtime.

## To publish (manual, by the publisher)

1. Install vsce once: `npm install -g @vscode/vsce`.
2. Create a publisher at https://marketplace.visualstudio.com/manage
   (needs a Microsoft account + an Azure DevOps personal access token with
   the **Marketplace (publish)** scope).
3. `vsce login braim` and paste the token.
4. From this folder: `vsce package` → produces `braimsec-scanner-0.1.0.vsix`.
   Smoke-test the .vsix locally first:
   `code --install-extension braimsec-scanner-0.1.0.vsix`.
5. `vsce publish` to go live.

Alternative without a Microsoft account: publish to
[Open VSX](https://open-vsx.org) with `npx ovsx publish` (needs an
Eclipse Foundation account + token); it works in VS Code, VSCodium and
most forks.

## Before publishing

- Bump `version` in `package.json` for every release.
- Fill in a real `publisher` id (currently the placeholder `braim`).
- Test the packaged .vsix against a real BraimSec server end to end:
  scan a workspace, click a finding, confirm the editor jumps to the line.
