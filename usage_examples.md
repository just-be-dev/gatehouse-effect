---
title: Examples
group: Documents
category: Guides
---

# Gatehouse-Effect Usage Examples

This document provides practical examples of how to use the gatehouse-effect library to implement various authorization patterns using [Effect](https://effect.website).

## 1. Basic Setup

First, let's define the types we'll use for our subjects (users), resources (documents), actions, and context.

```typescript
import { Effect, Match } from 'effect';
import {
  buildRbacPolicy,
  buildAbacPolicy,
  buildRebacPolicy,
  buildAndPolicy,
  buildOrPolicy,
  buildNotPolicy,
  makePolicy,
  checkPermissions,
  isGranted,
  getDisplayTrace,
  formatResult,
} from 'gatehouse-effect';

// Define types for your application
type User = {
  id: string;
  roles: string[]; // e.g., ["admin", "editor", "viewer"]
  department: string;
};

type Document = {
  id: string;
  ownerId: string;
  isPublic: boolean;
  requiredDepartment: string | null; // e.g., "HR", "Engineering"
};

type Action = "read" | "write" | "delete" | "comment";

type RequestContext = {
  ipAddress: string;
  timestamp: Date;
};

// Sample data
const adminUser: User = { id: "user-admin", roles: ["admin"], department: "IT" };
const editorUser: User = { id: "user-editor", roles: ["editor"], department: "Marketing" };
const viewerUser: User = { id: "user-viewer", roles: ["viewer"], department: "Sales" };
const guestUser: User = { id: "user-guest", roles: [], department: "External" };

const publicDoc: Document = { id: "doc-public", ownerId: editorUser.id, isPublic: true, requiredDepartment: null };
const privateDoc: Document = { id: "doc-private", ownerId: editorUser.id, isPublic: false, requiredDepartment: null };
const hrDoc: Document = { id: "doc-hr", ownerId: adminUser.id, isPublic: false, requiredDepartment: "HR" };

const sampleContext: RequestContext = { ipAddress: "192.168.1.100", timestamp: new Date() };
```

## 2. Role-Based Access Control (RBAC)

An RBAC policy grants access based on the roles assigned to the subject.

**Example:** Allow users with the _"editor"_ or _"admin"_ role to write, and users with _"viewer"_, _"editor"_, or _"admin"_ roles to read.

```typescript
const rbacPolicy = buildRbacPolicy<User, Document, Action, RequestContext, string>({
  name: "Standard RBAC Policy",
  // Resolvers can return plain values or Effect.Effect values
  requiredRolesResolver: (resource, action) =>
    Match.value(action).pipe(
      Match.when("read", () => ["viewer", "editor", "admin"]),
      Match.when("write", () => ["editor", "admin"]),
      Match.when("comment", () => ["editor", "admin"]),
      Match.when("delete", () => ["admin"]),
      Match.exhaustive
    ),
  userRolesResolver: (subject) => subject.roles,
});

// --- Evaluation ---
// Evaluate a single policy directly using Effect.runPromise
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
// To see *why* it was denied:
// console.log(formatResult(result2));
```

**Explanation:**

*   `buildRbacPolicy` creates an RBAC policy.
*   `requiredRolesResolver` and `userRolesResolver` can return plain values (`Role[]`) or `Effect.Effect<Role[]>`. Use plain values for simple lookups; use Effects for async or effectful operations.
*   Use `isGranted(result)` to check if a `PolicyEvalResult` grants access.
*   Use `formatResult(result)` to get a human-readable explanation.

## 3. Attribute-Based Access Control (ABAC)

An ABAC policy makes decisions based on attributes of the subject, resource, action, and context.

**Example:** Allow anyone to "read" a document if its `isPublic` attribute is true.

```typescript
const publicReadPolicy = buildAbacPolicy<User, Document, Action, RequestContext>({
  name: "Public Document Read Access",
  condition: ({ resource, action }) => action === "read" && resource.isPublic,
});

// --- Evaluation ---
// Guest tries to read a public document (Allowed by ABAC)
const result3 = await Effect.runPromise(
  publicReadPolicy.evaluateAccess({
    subject: guestUser,
    resource: publicDoc,
    action: "read",
    context: sampleContext,
  })
);
console.log(`Guest read publicDoc: ${isGranted(result3)}`); // Output: true

// Guest tries to read a private document (Denied by ABAC)
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

*   `buildAbacPolicy` creates an ABAC policy based on a `condition` function.
*   The `condition` function can return a plain `boolean` or `Effect.Effect<boolean>`.

## 4. Relationship-Based Access Control (ReBAC)

ReBAC policies grant access based on the relationship between the subject and the resource (e.g., owner, member).

**Example:** Allow a user to access a document only if they are the owner.

```typescript
const ownerPolicy = buildRebacPolicy<User, Document, Action, RequestContext>({
  name: "Owner Policy",
  relationship: "owner",
  resolver: ({ subject, resource }) => subject.id === resource.ownerId,
});

// --- Evaluation ---
// Editor accesses their own document (Allowed)
const result5 = await Effect.runPromise(
  ownerPolicy.evaluateAccess({
    subject: editorUser,
    resource: privateDoc, // Owned by editorUser
    action: "delete",
    context: sampleContext,
  })
);
console.log(`Editor delete own doc: ${isGranted(result5)}`); // Output: true

// Editor tries to access admin's document (Denied)
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

**Explanation:**

*   `buildRebacPolicy` defines access based on a named `relationship`.
*   The `resolver` can return a plain `boolean` or `Effect.Effect<boolean>` indicating whether the subject has the relationship with the resource.

## 5. Using `makePolicy`

`makePolicy` creates custom policies from individual predicate functions. All predicates are AND'd together. Omitted predicates default to true.

**Example:** Allow users in the "HR" department to "read" documents marked for "HR", but only during business hours.

```typescript
const isBusinessHours = (context: RequestContext): boolean => {
  const hour = context.timestamp.getHours();
  return hour >= 9 && hour < 17;
};

// Predicates can return a plain boolean or an Effect.Effect<boolean>
const hrAccessPolicy = makePolicy<User, Document, Action, RequestContext>("HR Department Access", {
  subject: (subject) => subject.department === "HR",
  resource: (resource) => resource.requiredDepartment === "HR",
  action: (action) => action === "read",
  context: (ctx) => isBusinessHours(ctx),
});

// --- Evaluation ---
const hrUser: User = { id: "user-hr", roles: ["viewer"], department: "HR" };
const outsideHoursContext: RequestContext = {
  ipAddress: "192.168.1.101",
  timestamp: new Date(2023, 10, 15, 18, 0, 0), // 6 PM
};

// HR User reading HR Doc during business hours (Allowed)
const result7 = await Effect.runPromise(
  hrAccessPolicy.evaluateAccess({
    subject: hrUser,
    resource: hrDoc,
    action: "read",
    context: sampleContext, // Assumed to be within business hours
  })
);
console.log(`HR User read HR Doc (Business Hours): ${isGranted(result7)}`); // Output: true

// HR User reading HR Doc outside business hours (Denied)
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

*   `makePolicy` takes a name and an options object with optional predicates: `subject`, `resource`, `action`, `context`, and `when`.
*   Each predicate can return a plain `boolean` or an `Effect.Effect<boolean>`. Use plain booleans for simple checks; use Effects when the predicate needs to perform async or effectful operations.
*   All provided predicates must return true for the policy to grant access.
*   Use `intent: 'deny'` to create policies that explicitly deny access when predicates match.
*   The `when` predicate receives all four arguments `{ subject, resource, action, context }` for cross-cutting conditions.

## 6. Combining Policies

You can combine existing policies using logical operators: AND, OR, NOT.

**Example:** Grant "comment" access if the user is the owner **AND** the document is not public, **OR** if the user is an "admin".

```typescript
// Policy 1: Is the user the owner? (ReBAC)
const isOwnerPolicy = buildRebacPolicy<User, Document, Action, RequestContext>({
  name: "IsOwner",
  relationship: "owner",
  resolver: ({ subject, resource }) => subject.id === resource.ownerId,
});

// Policy 2: Is the document private? (ABAC)
const isPrivatePolicy = buildAbacPolicy<User, Document, Action, RequestContext>({
  name: "IsPrivate",
  condition: ({ resource }) => !resource.isPublic,
});

// Policy 3: Is the user an admin? (RBAC)
const isAdminPolicy = buildRbacPolicy<User, Document, Action, RequestContext, string>({
  name: "IsAdmin",
  requiredRolesResolver: () => ["admin"],
  userRolesResolver: (subject) => subject.roles,
});

// Combine: (Owner AND Private)
const ownerAndPrivatePolicy = buildAndPolicy({
  name: "OwnerAndPrivate",
  policies: [isOwnerPolicy, isPrivatePolicy],
});

// Combine: (Owner AND Private) OR Admin
const finalCommentPolicy = buildOrPolicy({
  name: "CommentAccessLogic",
  policies: [ownerAndPrivatePolicy, isAdminPolicy],
});

// --- Evaluation ---
// Owner comments on their private doc (Allowed: Owner AND Private)
const result9 = await Effect.runPromise(
  finalCommentPolicy.evaluateAccess({
    subject: editorUser,
    resource: privateDoc, // Private, owned by editor
    action: "comment",
    context: sampleContext,
  })
);
console.log(`Owner comment private doc: ${isGranted(result9)}`); // Output: true

// Owner comments on their public doc (Denied: Not Private)
const result10 = await Effect.runPromise(
  finalCommentPolicy.evaluateAccess({
    subject: editorUser,
    resource: publicDoc, // Public, owned by editor
    action: "comment",
    context: sampleContext,
  })
);
console.log(`Owner comment public doc: ${isGranted(result10)}`); // Output: false

// Admin comments on a private doc they don't own (Allowed: Is Admin)
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

**Explanation:**

*   `buildAndPolicy` requires all its child policies to grant access.
*   `buildOrPolicy` requires at least one of its child policies to grant access.
*   `buildNotPolicy` inverts the result of its child policy (Grant → Deny, Deny → Grant).
*   Policies can be nested to create complex logic.
*   To restrict combined logic to a specific action, wrap it with `makePolicy`:
    ```typescript
    const commentOnly = makePolicy<User, Document, Action, RequestContext>("CommentOnly", {
      action: (action) => action === "comment",
      when: ({ subject, resource, action, context }) =>
        Effect.map(
          finalCommentPolicy.evaluateAccess({ subject, resource, action, context }),
          (result) => isGranted(result)
        ),
    });
    ```

## 7. Using `checkPermissions`

`checkPermissions` is the primary way to evaluate multiple policies together. It takes an array of policies and returns a curried evaluator function. Policies are evaluated sequentially with **first-grant-wins** semantics.

The result is typed in the Effect channels:
- **Success channel:** `AccessGranted` — a policy granted access
- **Error channel:** `AccessDenied | NoPoliciesError` — all policies denied, or no policies configured

```typescript
// Create the evaluator with multiple policies
const check = checkPermissions([publicReadPolicy, rbacPolicy]);

// --- Granted access ---
const program = Effect.gen(function* () {
  // Guest reading a public doc — publicReadPolicy grants access
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
// Use Effect.merge to unify success and error channels for inspection
const program2 = Effect.gen(function* () {
  const result = yield* check({
    subject: guestUser,
    resource: privateDoc,
    action: "write",
    context: sampleContext,
  }).pipe(Effect.merge);

  if (result._tag === "AccessGranted") {
    console.log("Access Granted!");
  } else {
    console.log("Access Denied.");
    console.log(getDisplayTrace(result)); // Detailed evaluation trace
  }
});

await Effect.runPromise(program2);

// --- No policies configured ---
const emptyCheck = checkPermissions<User, Document, Action, RequestContext>([]);

const program3 = Effect.gen(function* () {
  const result = yield* emptyCheck({
    subject: adminUser,
    resource: publicDoc,
    action: "read",
    context: sampleContext,
  }).pipe(Effect.merge);

  console.log(result._tag); // Output: NoPoliciesError
});

await Effect.runPromise(program3);
```

**Explanation:**

*   `checkPermissions(policies)` returns a function `(args) => Effect<AccessGranted, AccessDenied | NoPoliciesError>`.
*   On success, you get an `AccessGranted` with `policyType`, `reason`, and `trace`.
*   On failure, the error is `AccessDenied` (with `reason` and `trace`) or `NoPoliciesError`.
*   Use `Effect.merge` to bring the error into the success channel for pattern matching on `_tag`.
*   Use `getDisplayTrace(result)` to get a formatted trace string showing which policies were evaluated and their outcomes.
*   Use `formatResult(policyEvalResult)` to format individual `PolicyEvalResult` values.

## 8. Running Effects

All evaluations in gatehouse-effect return `Effect` values. You need to run them to get results:

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

// Option 3: pipe with Effect.merge for checkPermissions
const check = checkPermissions([rbacPolicy, publicReadPolicy]);
const merged = check({ subject, resource, action, context }).pipe(Effect.merge);
const accessResult = await Effect.runPromise(merged);
// accessResult is AccessGranted | AccessDenied | NoPoliciesError
```
