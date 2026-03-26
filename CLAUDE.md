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

Single-module library (`src/gatehouse.ts`) exporting:

- **Policy types:** `buildRbacPolicy`, `buildAbacPolicy`, `buildRebacPolicy` — factory functions for specific authorization models
- **Combinators:** `buildAndPolicy`, `buildOrPolicy`, `buildNotPolicy` — compose policies with boolean logic
- **PolicyBuilder** — fluent builder for custom policies with subject/resource/action/context predicates
- **PermissionChecker** — evaluates multiple policies sequentially (first-grant-wins), returns `Effect<AccessGranted, AccessDenied | NoPoliciesError>`

All policy predicates and resolvers return `Effect.Effect<T>` (not raw values or Promises). `AccessDenied` and `NoPoliciesError` are `Data.TaggedError` types in the Effect error channel. Use `Effect.merge` to unify success/error channels for inspection.

<!-- effect-solutions:start -->
## Effect Best Practices

**IMPORTANT:** Always consult effect-solutions before writing Effect code.

1. Run `bunx effect-solutions list` to see available guides
2. Run `bunx effect-solutions show <topic>...` for relevant patterns (supports multiple topics)
3. Search `~/.local/share/effect-solutions/effect` for real implementations

Topics: quick-start, project-setup, tsconfig, basics, services-and-layers, data-modeling, error-handling, config, testing, cli.

Never guess at Effect patterns - check the guide first.
<!-- effect-solutions:end -->
