# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

gatehouse-effect is an Effect-TS port of [gatehouse-ts](https://github.com/9Morello/gatehouse-ts), a TypeScript library for building and managing authorization policies. It supports RBAC, ABAC, ReBAC, and composable policy combinators (AND, OR, NOT).

## Commands

- **Install:** `bun install`
- **Build:** `bun run build` (runs `tsc`)
- **Test:** `bun test`
- **Single test:** `bun test tests/index.test.ts`
- **Typecheck:** `bun run typecheck`

## Architecture

Single-module functional library (`src/gatehouse.ts`). All data types are pure data (no methods) — use standalone functions to inspect results.

- **Policy factories:** `buildRbacPolicy`, `buildAbacPolicy`, `buildRebacPolicy` — create policies for specific authorization models
- **Combinators:** `anyPolicy` — OR (any sub-policy grants); `everyPolicy` — AND (all must grant); `invertPolicy` — invert a single policy; `combinePolicy(({ and, or, not }) => ...)` — compose with boolean logic
- **`makePolicy`** — creates custom policies from predicate functions (subject/resource/action/context/when)
- **`checkPermissions`** — curried function: takes policies array, returns evaluator. First-grant-wins. Returns `Effect<AccessGranted, AccessDenied | NoPoliciesError>`
- **Result functions:** `isGranted`, `formatResult`, `getDisplayTrace`, `formatTrace` — operate on `PolicyEvalResult` or access results

All predicates/resolvers return `Effect.Effect<T>`. Errors use `Schema.TaggedErrorClass`, results use `Schema.TaggedClass`/`Data.TaggedClass`. Use `_tag` or `Match.valueTags` for discrimination.

<!-- effect-solutions:start -->
## Effect Best Practices

**IMPORTANT:** Always consult effect-solutions before writing Effect code.

1. Run `bunx effect-solutions list` to see available guides
2. Run `bunx effect-solutions show <topic>...` for relevant patterns (supports multiple topics)
3. Search `~/.local/share/effect-solutions/effect` for real implementations

Topics: quick-start, project-setup, tsconfig, basics, services-and-layers, data-modeling, error-handling, config, testing, cli.

Never guess at Effect patterns - check the guide first.
<!-- effect-solutions:end -->
