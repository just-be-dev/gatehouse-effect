# gatehouse-effect

A flexible authorization library for [Effect-TS](https://effect.website) that combines role-based (RBAC), attribute-based (ABAC), and relationship-based (ReBAC) access control policies.

Based on the [Gatehouse authorization library for Rust](https://github.com/thepartly/gatehouse/) — credits for the original API design, Rust implementation, and usage instructions go to [Hardbyte](https://hardbyte.nz/) and [Partly](https://partly.com/). The TypeScript implementation was originally created by [gr4vityWall](https://github.com/9Morello) as [gatehouse-ts](https://github.com/9Morello/gatehouse-ts). This project is an Effect-TS port of that work.

## Features

- **Multi-paradigm Authorization**: Support for RBAC, ABAC, and ReBAC patterns
- **Policy Composition**: Combine policies with logical operators (`AND`, `OR`, `NOT`)
- **Effect-native**: All evaluations return `Effect.Effect`, integrating naturally with Effect pipelines
- **Detailed Evaluation Tracing**: Complete decision trace for debugging and auditing
- **Type Safety**: Schema-driven types for subjects, resources, actions, and contexts

## Quick Start

### Install

```bash
bun add gatehouse-effect effect
```

### Define your domain

```typescript
import { Effect, Schema } from "effect";
import {
  policyFactory,
  checkPermissions,
  isGranted,
  getDisplayTrace,
} from "gatehouse-effect";

const User = Schema.Struct({
  id: Schema.String,
  roles: Schema.Array(Schema.String),
  department: Schema.String,
});

const Document = Schema.Struct({
  id: Schema.String,
  ownerId: Schema.String,
  isPublic: Schema.Boolean,
});

const Action = Schema.Literal("read", "write", "delete");

const RequestContext = Schema.Struct({
  ipAddress: Schema.String,
  timestamp: Schema.DateFromSelf,
});

// Create a typed policy factory — all types are inferred from schemas
const define = policyFactory({
  subject: User,
  resource: Document,
  action: Action,
  context: RequestContext,
});
```

### Build an RBAC policy

```typescript
const rbacPolicy = define.rbac("Standard RBAC", {
  roles: {
    read: ["viewer", "editor", "admin"],
    write: ["editor", "admin"],
    delete: ["admin"],
  },
  userRoles: (subject) => subject.roles,
});
```

### Evaluate access

```typescript
const editorUser = { id: "user-1", roles: ["editor"], department: "Marketing" };
const doc = { id: "doc-1", ownerId: "user-1", isPublic: false };
const ctx = { ipAddress: "192.168.1.100", timestamp: new Date() };

const evaluate = checkPermissions([rbacPolicy]);

const result = await Effect.runPromise(
  evaluate({
    subject: editorUser,
    resource: doc,
    action: "write",
    context: ctx,
  })
);

// If we get here, access was granted (AccessDenied would be in the error channel)
console.log(getDisplayTrace(result)); // detailed evaluation trace
```

### Compose policies

```typescript
import { anyPolicy, everyPolicy, invertPolicy, combinePolicy } from "gatehouse-effect";

// Any sub-policy grants access (OR)
const canAccess = anyPolicy([rbacPolicy, abacPolicy]);
// canAccess.name → "RbacPolicy | AbacPolicy"

// All sub-policies must grant access (AND)
const strictAccess = everyPolicy([rbacPolicy, abacPolicy]);
// strictAccess.name → "RbacPolicy & AbacPolicy"

// Invert a single policy
const notGuest = invertPolicy(guestPolicy);
// notGuest.name → "!GuestPolicy"

// Compose with and/or/not in a single expression
const policy = combinePolicy(({ and, or, not }) =>
  and(rbacPolicy, or(abacPolicy, not(guestPolicy)))
);
// policy.name → "RbacPolicy & (AbacPolicy | !GuestPolicy)"
```

For more examples covering ABAC, ReBAC, and advanced composition, see [usage_examples.md](usage_examples.md).
