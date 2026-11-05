## What this changes

<!-- One or two sentences. Link the issue if there is one: Fixes #123 -->

## How I tested it

<!-- e.g. "Ran against Ubuntu 24.04 with fail2ban 1.0.2", "added a case to tests/analyze.test.ts" -->

## Checklist

- [ ] `pnpm build` and `pnpm test` pass
- [ ] The probe is still read-only POSIX `sh` (if `electron/collector.ts` changed)
- [ ] Every value interpolated into a remote command is validated
- [ ] `CHANGELOG.md` is updated under **Unreleased** (if users will notice)
- [ ] Screenshots are refreshed with `pnpm screenshot` (if the UI changed)
