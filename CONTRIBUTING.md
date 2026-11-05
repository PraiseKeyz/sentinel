# Contributing to Sentinel

Thanks for helping make servers a little safer. Bug reports, new detection rules, UI work and docs are all welcome.

## Before you start

- **Found a security vulnerability?** Don't open a public issue. Follow [SECURITY.md](SECURITY.md).
- **Bigger change?** Open an issue first so we can agree on the approach before you spend time on it.
- **Small fix?** Go straight to a pull request.

## Setup

You need Node.js 22 or newer and pnpm 12.

```bash
git clone https://github.com/PraiseKeyz/sentinel.git
cd sentinel
pnpm install
pnpm dev
```

The first `pnpm dev` downloads Electron (about 115 MB). To work on the UI without Electron or real servers, run `pnpm exec vite` and open http://localhost:5173. It loads the demo data in `src/mock.ts`.

## Project layout

| Path | What lives there |
|---|---|
| `electron/collector.ts` | The read-only shell probe that runs on each server |
| `electron/parse.ts` | Turns probe output into `Metrics` |
| `electron/analyze.ts` | Detection rules: `Metrics` → `Finding[]` |
| `electron/engine.ts` | Scheduling, scoring, auto-ban and whitelist protection |
| `electron/ssh.ts` | SSH connection pool and host-key pinning |
| `electron/main.ts`, `preload.ts` | Electron window and the IPC bridge to the UI |
| `shared/types.ts` | Types shared by the engine and the UI |
| `src/` | React UI |
| `tests/` | Unit tests (Node's built-in test runner) |

## Adding a detection rule

1. If the rule needs new data, add a section to the probe in `electron/collector.ts`. It must be POSIX `sh` (it runs under dash on Debian and Ubuntu), read-only, and silent on errors (`2>/dev/null`).
2. Parse the new section in `electron/parse.ts` and add the field to `Metrics` in `shared/types.ts`.
3. Add the rule in `electron/analyze.ts`. Give the finding a **stable `id`**, because notifications use it to tell new findings from known ones. Write the `detail` text in plain language and include the fix where there is one.
4. Set `bannable: true` only when the IP is clearly the attacker and is not spoofable. Don't set it for SYN floods, for example.
5. Add a case to `tests/analyze.test.ts` and update the demo data in `src/mock.ts` if the UI shows something new.

## Ground rules for the probe and bans

These are hard requirements, because Sentinel runs with high privileges on other people's servers:

- The probe never writes, installs or restarts anything.
- The only commands that change a server are `fail2ban-client set <jail> banip|unbanip <ip>`. Validate every value interpolated into a remote command (see `JAIL_RE` and `isIP` in `engine.ts`).
- Never bypass `Engine.isProtected()`. The user's own IP, the whitelist and the monitored servers must never be banned.

## Checks before you open a pull request

```bash
pnpm build   # type-checks the engine and the UI, then bundles
pnpm test
```

CI runs the same checks on macOS, Windows and Linux.

- Keep pull requests focused on one change.
- Match the existing code style. `.editorconfig` covers the basics: 2-space indents and single quotes in TypeScript.
- Update `CHANGELOG.md` under **Unreleased** for anything users will notice.
- If you change the UI, run `pnpm screenshot` to refresh the images in `docs/`.

## Commit messages

Use short, imperative subjects, such as `Detect HTTP floods from Caddy logs` or `Fix disk parsing for mount points with spaces`.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
