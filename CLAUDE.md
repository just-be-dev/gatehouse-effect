# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

gatehouse-effect is an Effect-TS port of [gatehouse-ts](https://github.com/9Morello/gatehouse-ts), a TypeScript library for building and managing authorization policies. It supports RBAC, ABAC, ReBAC, and composable policy combinators (AND, OR, NOT).

## Commands

Run from the repo root. `mise.toml` pins Bun and Node.js and installs the locked dependencies, so setup is one step:

```sh
mise trust && mise install
mise run check        # typecheck, lint, test, format:check
mise run test:watch
mise run format       # rewrites files; format:check only reports
mise run build        # emits dist/
mise run docs         # regenerates the TypeDoc site in docs/
```

Target one test file or name with `bun run test tests/index.test.ts` or `bun run test -t "RBAC"`. `mise run deploy` publishes the docs site, so only run it with approval.

## Tooling

Every dependency in `package.json` is pinned to an exact version and `bun.lock` locks the rest. Upgrades are deliberate.

| Tool                                | Role                                                        |
| ----------------------------------- | ----------------------------------------------------------- |
| Bun / mise                          | Package manager, script runner, tools and tasks             |
| Node.js / Vitest / `@effect/vitest` | Test runtime, runner, and scoped Effect testing             |
| tsrs                                | Native TypeScript 7 checker (`tsrs --noEmit`) and the build |
| `@effect/tsgo` tsrs patch           | Effect diagnostics in the checker and language server       |
| Oxlint + Effect plugin              | Linting, including Effect rules                             |
| Oxfmt                               | Formatting                                                  |
| TypeDoc                             | API docs site in `docs/`                                    |

- **Type checking:** [tsrs](https://github.com/oxc-project/tsrs) is a Rust port of the TypeScript 7 compiler and language server. The `prepare` script runs `effect-tsgo patch --tsrs --no-typescript`, which swaps the installed tsrs binary for the Effect-patched build that `@effect/tsgo` ships for that exact version. Each `@effect/tsgo` release supports specific tsrs versions (see its README), so upgrade them together and confirm `bun install` prints `Patched tsrs` or `tsrs skipped because its hash matches the replacement`.
- **Build:** `tsrs -p tsconfig.build.json` emits `dist/gatehouse.js`, declarations, and source maps. `effect` stays an external import; it isn't bundled.
- **`tsconfig.json`:** strict library settings (`NodeNext`, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`) and the `@effect/language-service` plugin, which the patched tsrs reads. An override allows the unstable `@effect/vitest` API in test files only.
- **Tests:** Vitest discovers `tests/**/*.test.ts` (`vitest.config.ts`). Import helpers from `@effect/vitest`. Use `it.effect` for Effect programs (test services and automatic scope cleanup), `it.live` when real time is needed, and plain `it` for synchronous tests.
- **Lint:** `oxlint.config.ts` loads the Effect plugin and forbids non-null assertions, `any`, and `as` casts (decode with Schema, narrow with a type guard, or use `satisfies`). Prefix intentionally unused names with `_`.
- **Format:** Oxfmt defaults; `.oxfmtrc.json` skips the generated `docs/`. Oxlint skips it too.
- **TypeDoc:** reads `typedoc.json`. It needs the `typescript` package, which Bun installs as TypeDoc's peer; nothing else uses it.
- **Effect overrides:** `effect` is pinned in `dependencies` and `overrides`. The Effect Oxlint plugin still depends on `effect@4.0.0`; the override keeps a single Effect instance. Recheck it on every upgrade.
- **Editors:** the TypeScript server must be the workspace tsrs (`node_modules/.bin/tsrs --lsp --stdio`) to show the Effect diagnostics `mise run typecheck` reports. `.zed/settings.json` (needs Zed's "TypeScript Language Server" extension), `.nvim.lua` (Neovim 0.11+ with `exrc`), and `.lazy.lua` (LazyVim) set this up. In VS Code with the TypeScript 7 extension, set `"js/ts.experimental.useTsgo": true` and `"js/ts.tsdk.path": "./node_modules/tsrs/tsdk"`. Restart the language server after upgrading tsrs or `@effect/tsgo`.
- **CI:** `.github/workflows/ci.yml` runs `bun install --frozen-lockfile`, `mise run check`, and `mise run build` on pushes to `main` and on pull requests. It has read-only permissions and no secrets.

## Architecture

Single-module functional library (`src/gatehouse.ts`). All data types are pure data (no methods) — use standalone functions to inspect results.

- **Policy factories:** `buildRbacPolicy`, `buildAbacPolicy`, `buildRebacPolicy` — create policies for specific authorization models
- **Combinators:** `anyPolicy` — OR (any sub-policy grants); `everyPolicy` — AND (all must grant); `invertPolicy` — invert a single policy; `combinePolicy(({ and, or, not }) => ...)` — compose with boolean logic
- **`makePolicy`** — creates custom policies from predicate functions (subject/resource/action/context/when)
- **`checkPermissions`** — curried function: takes policies array, returns evaluator. First-grant-wins. Returns `Effect<AccessGranted, AccessDenied | NoPoliciesError>`
- **Result functions:** `isGranted`, `formatResult`, `getDisplayTrace`, `formatTrace` — operate on `PolicyEvalResult` or access results

All predicates/resolvers return `Effect.Effect<T>`. Errors use `Schema.TaggedError`, results use `Schema.TaggedClass`/`Data.TaggedClass`. Use `_tag` or `Match.valueTags` for discrimination.

<!-- effect-solutions:start -->
## Effect Best Practices

**IMPORTANT:** Always consult effect-solutions before writing Effect code.

1. Run `mise run effect-solutions list` to see available guides
2. Run `mise run effect-solutions show <topic>...` for relevant patterns (supports multiple topics)
3. Search `~/.local/share/effect-solutions/effect` for real implementations

Topics: quick-start, project-setup, tsconfig, basics, services-and-layers, data-modeling, error-handling, config, testing, cli.

Never guess at Effect patterns - check the guide first.
<!-- effect-solutions:end -->
