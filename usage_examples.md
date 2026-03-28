---
title: Examples
group: Documents
category: Guides
---

# Gatehouse-Effect Usage Examples

This document provides practical examples of how to use the gatehouse-effect library to implement various authorization patterns using [Effect](https://effect.website).

## 1. Basic Setup

Define your domain with Effect Schemas. Types are inferred automatically — no generic parameters needed anywhere.

```typescript
import { Effect, Schema } from 'effect';
import {
  policyFactory,
  anyPolicy,
  everyPolicy,
  combinePolicy,
  invertPolicy,
  checkPermissions,
  isGranted,
  getDisplayTrace,
  formatResult,
} from 'gatehouse-effect';

// Define your domain as schemas
const User = Schema.Struct({
  id: Schema.String,
  roles: Schema.Array(Schema.String),
  department: Schema.String,
});

const Document = Schema.Struct({
  id: Schema.String,
  ownerId: Schema.String,
  isPublic: Schema.Boolean,
  requiredDepartment: Schema.NullOr(Schema.String),
});

const Action = Schema.Literal("read", "write", "delete", "comment");

const RequestContext = Schema.Struct({
  ipAddress: Schema.String,
  timestamp: Schema.DateFromSelf,
});

// Create a typed policy factory — all types are inferred from the schemas
const define = policyFactory({
  subject: User,
  resource: Document,
  action: Action,
  context: RequestContext,
});

// Sample data
const adminUser = { id: "user-admin", roles: ["admin"], department: "IT" };
const editorUser = { id: "user-editor", roles: ["editor"], department: "Marketing" };
const viewerUser = { id: "user-viewer", roles: ["viewer"], department: "Sales" };
const guestUser = { id: "user-guest", roles: [] as string[], department: "External" };

const publicDoc = { id: "doc-public", ownerId: editorUser.id, isPublic: true, requiredDepartment: null };
const privateDoc = { id: "doc-private", ownerId: editorUser.id, isPublic: false, requiredDepartment: null };
const hrDoc = { id: "doc-hr", ownerId: adminUser.id, isPublic: false, requiredDepartment: "HR" };

const sampleContext = { ipAddress: "192.168.1.100", timestamp: new Date() };
```

## 2. Role-Based Access Control (RBAC)

Use `define.rbac` with a declarative role map. The keys are enforced by the `Action` schema — TypeScript requires exhaustive coverage of all action literals.

```typescript
const rbacPolicy = define.rbac("Standard RBAC Policy", {
  roles: {
    read: ["viewer", "editor", "admin"],
    write: ["editor", "admin"],
    comment: ["editor", "admin"],
    delete: ["admin"],
  },
  userRoles: (subject) => subject.roles,
});

// --- Evaluation ---
const result = await Effect.runPromise(
  rbacPolicy.evaluateAccess({
    subject: editorUser,
    resource: privateDoc,
    action: "write",
    context: sampleContext,
  })
);
console.log(`Editor write privateDoc: ${isGranted(result)}`); // Output: true

const result2 = await Effect.runPromise(
  rbacPolicy.evaluateAccess({
    subject: viewerUser,
    resource: publicDoc,
    action: "write",
    context: sampleContext,
  })
);
console.log(`Viewer write publicDoc: ${isGranted(result2)}`); // Output: false
```

**Explanation:**

*   `define.rbac` creates an RBAC policy with a static role map.
*   The role map keys must cover every action literal from the `Action` schema — a missing key is a type error.
*   `userRoles` can return a plain array or `Effect.Effect<Role[]>` for async role lookups.

## 3. Attribute-Based Access Control (ABAC)

Use `define` with predicate functions and/or action literals to create attribute-based policies.

**Example:** Allow anyone to "read" a document if its `isPublic` attribute is true.

```typescript
const publicReadPolicy = define("Public Document Read Access", {
  action: "read",
  resource: (r) => r.isPublic,
});

// --- Evaluation ---
const result3 = await Effect.runPromise(
  publicReadPolicy.evaluateAccess({
    subject: guestUser,
    resource: publicDoc,
    action: "read",
    context: sampleContext,
  })
);
console.log(`Guest read publicDoc: ${isGranted(result3)}`); // Output: true

const result4 = await Effect.runPromise(
  publicReadPolicy.evaluateAccess({
    subject: guestUser,
    resource: privateDoc,
    action: "read",
    context: sampleContext,
  })
);
console.log(`Guest read privateDoc: ${isGranted(result4)}`); // Output: false
```

**Explanation:**

*   `action: "read"` matches only the "read" action — no function needed.
*   `action: ["read", "write"]` matches multiple actions.
*   `resource: (r) => r.isPublic` is a predicate that returns a plain `boolean` or `Effect.Effect<boolean>`.
*   All provided predicates are AND'd together.

## 4. Relationship-Based Access Control (ReBAC)

Use `define.rebac` to grant access based on a named relationship between subject and resource.

**Example:** Allow a user to access a document only if they are the owner.

```typescript
const ownerPolicy = define.rebac("Owner Policy", {
  relationship: "owner",
  resolver: ({ subject, resource }) => subject.id === resource.ownerId,
});

// --- Evaluation ---
const result5 = await Effect.runPromise(
  ownerPolicy.evaluateAccess({
    subject: editorUser,
    resource: privateDoc, // Owned by editorUser
    action: "delete",
    context: sampleContext,
  })
);
console.log(`Editor delete own doc: ${isGranted(result5)}`); // Output: true

const result6 = await Effect.runPromise(
  ownerPolicy.evaluateAccess({
    subject: editorUser,
    resource: hrDoc, // Owned by adminUser
    action: "delete",
    context: sampleContext,
  })
);
console.log(`Editor delete admin's doc: ${isGranted(result6)}`); // Output: false
```

## 5. Custom Policies with `define`

`define` creates custom policies from individual predicates. All predicates are AND'd together. Omitted predicates default to true.

**Example:** Allow users in the "HR" department to "read" documents marked for "HR", but only during business hours.

```typescript
const isBusinessHours = (context: { timestamp: Date }): boolean => {
  const hour = context.timestamp.getHours();
  return hour >= 9 && hour < 17;
};

const hrAccessPolicy = define("HR Department Access", {
  subject: (s) => s.department === "HR",
  resource: (r) => r.requiredDepartment === "HR",
  action: "read",
  context: (ctx) => isBusinessHours(ctx),
});

// --- Evaluation ---
const hrUser = { id: "user-hr", roles: ["viewer"], department: "HR" };
const outsideHoursContext = { ipAddress: "192.168.1.101", timestamp: new Date(2023, 10, 15, 18, 0, 0) };

const result7 = await Effect.runPromise(
  hrAccessPolicy.evaluateAccess({
    subject: hrUser,
    resource: hrDoc,
    action: "read",
    context: sampleContext, // Assumed within business hours
  })
);
console.log(`HR User read HR Doc (Business Hours): ${isGranted(result7)}`); // Output: true

const result8 = await Effect.runPromise(
  hrAccessPolicy.evaluateAccess({
    subject: hrUser,
    resource: hrDoc,
    action: "read",
    context: outsideHoursContext,
  })
);
console.log(`HR User read HR Doc (Outside Hours): ${isGranted(result8)}`); // Output: false
```

**Explanation:**

*   Predicates: `subject`, `resource`, `action`, `context`, and `when`.
*   Each predicate can return a plain `boolean` or an `Effect.Effect<boolean>`.
*   `action` can also be a literal (`"read"`) or array (`["read", "write"]`) instead of a function.
*   Use `intent: 'deny'` to create policies that explicitly deny access when predicates match.
*   The `when` predicate receives all four arguments `{ subject, resource, action, context }` for cross-cutting conditions.

## 6. Combining Policies

Combine existing policies using logical operators: AND, OR, NOT.

**Example:** Grant "comment" access if the user is the owner **AND** the document is not public, **OR** if the user is an "admin".

```typescript
const isOwnerPolicy = define.rebac("IsOwner", {
  relationship: "owner",
  resolver: ({ subject, resource }) => subject.id === resource.ownerId,
});

const isPrivatePolicy = define("IsPrivate", {
  resource: (r) => !r.isPublic,
});

const isAdminPolicy = define.rbac("IsAdmin", {
  roles: { read: ["admin"], write: ["admin"], comment: ["admin"], delete: ["admin"] },
  userRoles: (s) => s.roles,
});

// Combine: (Owner AND Private) OR Admin
const finalCommentPolicy = define.combine(({ and, or }) =>
  or(and(isOwnerPolicy, isPrivatePolicy), isAdminPolicy)
);
// finalCommentPolicy.name → "(IsOwner & IsPrivate) | IsAdmin"

// --- Evaluation ---
const result9 = await Effect.runPromise(
  finalCommentPolicy.evaluateAccess({
    subject: editorUser,
    resource: privateDoc, // Private, owned by editor
    action: "comment",
    context: sampleContext,
  })
);
console.log(`Owner comment private doc: ${isGranted(result9)}`); // Output: true

const result10 = await Effect.runPromise(
  finalCommentPolicy.evaluateAccess({
    subject: editorUser,
    resource: publicDoc, // Public, owned by editor
    action: "comment",
    context: sampleContext,
  })
);
console.log(`Owner comment public doc: ${isGranted(result10)}`); // Output: false

const result11 = await Effect.runPromise(
  finalCommentPolicy.evaluateAccess({
    subject: adminUser,
    resource: privateDoc, // Private, owned by editor
    action: "comment",
    context: sampleContext,
  })
);
console.log(`Admin comment private doc: ${isGranted(result11)}`); // Output: true
```

You can also use `anyPolicy` and `everyPolicy` directly for simpler cases:

```typescript
// Any sub-policy grants access (OR)
const ownerOrAdmin = anyPolicy([isOwnerPolicy, isAdminPolicy]);
// ownerOrAdmin.name → "IsOwner | IsAdmin"

// All sub-policies must grant access (AND)
const ownerAndPrivate = everyPolicy([isOwnerPolicy, isPrivatePolicy]);
// ownerAndPrivate.name → "IsOwner & IsPrivate"

// With a custom name
const namedPolicy = anyPolicy("CanComment", [isOwnerPolicy, isAdminPolicy]);
```

**Explanation:**

*   `anyPolicy(policies)` grants access if **any** sub-policy grants access (OR).
*   `everyPolicy(policies)` grants access only if **all** sub-policies grant access (AND).
*   `invertPolicy(policy)` inverts a single policy's result.
*   `combinePolicy(({ and, or, not }) => ...)` composes policies with boolean logic in a single expression.
*   `define.combine(...)` is the factory-bound version — types flow automatically.
*   Names are auto-generated from the expression: `A & (B | !C)`.
*   Pass an optional name as the first argument: `combinePolicy("Name", ({ and }) => ...)`.
*   Policies from the factory work seamlessly with combinators.
*   To restrict combined logic to a specific action, wrap it:
    ```typescript
    const commentOnly = define("CommentOnly", {
      action: "comment",
      when: ({ subject, resource, action, context }) =>
        Effect.map(
          finalCommentPolicy.evaluateAccess({ subject, resource, action, context }),
          (result) => isGranted(result)
        ),
    });
    ```

## 7. Using `checkPermissions`

`checkPermissions` evaluates multiple policies sequentially with **first-grant-wins** semantics. The result uses Effect's error channel for access control decisions:

- **Success channel:** `AccessGranted`
- **Error channel:** `AccessDenied | NoPoliciesError`

```typescript
const check = checkPermissions([publicReadPolicy, rbacPolicy]);

// --- Granted access ---
const program = Effect.gen(function* () {
  const granted = yield* check({
    subject: guestUser,
    resource: publicDoc,
    action: "read",
    context: sampleContext,
  });
  console.log(`Guest read publicDoc: ${granted._tag}`); // Output: AccessGranted
  console.log(`Granted by: ${granted.policyType}`);      // Output: Public Document Read Access
});

await Effect.runPromise(program);

// --- Denied access ---
// Use Effect.catch to handle the error channel for inspection
const program2 = Effect.gen(function* () {
  const result = yield* check({
    subject: guestUser,
    resource: privateDoc,
    action: "write",
    context: sampleContext,
  }).pipe(Effect.catch((e) => Effect.succeed(e)));

  if (result._tag === "AccessGranted") {
    console.log("Access Granted!");
  } else {
    console.log("Access Denied.");
    console.log(getDisplayTrace(result)); // Detailed evaluation trace
  }
});

await Effect.runPromise(program2);
```

**Explanation:**

*   `checkPermissions(policies)` returns a function `(args) => Effect<AccessGranted, AccessDenied | NoPoliciesError>`.
*   On success, you get an `AccessGranted` with `policyType`, `reason`, and `trace`.
*   On failure, the error is `AccessDenied` (with `reason` and `trace`) or `NoPoliciesError`.
*   Use `Effect.catch` to bring the error into the success channel for pattern matching on `_tag`.
*   Use `getDisplayTrace(result)` for a formatted trace of which policies were evaluated.

## 8. Running Effects

All evaluations return `Effect` values. Run them to get results:

```typescript
// Option 1: Effect.runPromise — runs the effect and returns a Promise
const result = await Effect.runPromise(
  rbacPolicy.evaluateAccess({ subject, resource, action, context })
);

// Option 2: Effect.gen — compose multiple effects together
const program = Effect.gen(function* () {
  const policyResult = yield* rbacPolicy.evaluateAccess({ subject, resource, action, context });
  if (isGranted(policyResult)) {
    // proceed...
  }
});
await Effect.runPromise(program);

// Option 3: pipe with Effect.catch for checkPermissions
const check = checkPermissions([rbacPolicy, publicReadPolicy]);
const accessResult = await Effect.runPromise(
  check({ subject, resource, action, context }).pipe(
    Effect.catch((e) => Effect.succeed(e))
  )
);
// accessResult is AccessGranted | AccessDenied | NoPoliciesError
```
