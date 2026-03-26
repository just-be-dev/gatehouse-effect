# Gatehouse-TS

Gatehouse-TS is a flexible, zero-dependencies authorization library written in TypeScript. It combines role-based (RBAC), attribute-based (ABAC), and relationship-based (ReBAC) access control policies. Port of the [Gatehouse authorization library for Rust](https://github.com/thepartly/gatehouse/). The original authors did a fantastic job at creating an easy to use API, and were kind enough to let this library be named after Gatehouse.

Credits for the original API design, Rust implementation and usage instructions go to [Hardbyte](https://hardbyte.nz/) and [Partly](https://partly.com/). The TypeScript implementation was originally created by [gr4vityWall](https://github.com/9Morello) as [gatehouse-ts](https://github.com/9Morello/gatehouse-ts). This project is an Effect-TS port of that work.

## Features
- **Multi-paradigm Authorization**: Support for RBAC, ABAC, and ReBAC patterns
- **Policy Composition**: Combine policies with logical operators (`AND`, `OR`, `NOT`)
- **No additional runtime dependencies**: this library doesn't depend on any third-party libraries.
- **Trivially embeddable**: all the implementation resides inside the `src/index.ts` file, written in easy-to-follow TypeScript. Feel free to copy it directly to your project and modify it to better suit your needs. 
- **Detailed Evaluation Tracing**: Complete decision trace for debugging and auditing.
- **Fluent Builder API**: Construct custom policies with a PolicyBuilder.
- **Type Safety**: Strongly typed resources/actions/contexts.

### Documentation

[Click here](https://9morello.github.io/gatehouse-ts/) to browse the documentation.

## Quick Start

Here is an example of how to build a role-based `Policy` and evaluate access with it.

```typescript
import {
    buildRbacPolicy,
    PermissionChecker
  } from 'gatehouse-ts';
  
  type User = {
    id: number;
    roles: string[]; // e.g., ["admin", "editor", "viewer"]
    department: string;
  };
  
  type Document = {
    id: number;
    ownerId: number;
    isPublic: boolean;
    requiredDepartment: string | null; // e.g., "HR", "Engineering"
  };
  
  type Action = "read" | "write" | "delete" | "comment";
  
  type RequestContext = {
    ipAddress?: string;
    timestamp?: Date;
  };
  
  const rbacPolicy = buildRbacPolicy<User, Document, Action, RequestContext, string>({
    name: "Standard RBAC Policy",
    requiredRolesResolver: (resource:Document, action:Action) => {
      // This function determines which roles are needed for a given resource and action.
      // Here, it's simplified and only depends on the action.
      switch (action) {
        case "read":
          return ["viewer", "editor", "admin"];
        case "write":
        case "comment":
          return ["editor", "admin"];
        case "delete":
          return ["admin"];
        default:
          return []; // Deny unknown actions
      }
    },
      // This function extracts the roles from the subject (User).
    userRolesResolver: (subject:User) => subject.roles,
  });
  
  const permissionChecker = new PermissionChecker<User, Document, Action, RequestContext>();

  // Add the policy to the checker
  permissionChecker.addPolicy(rbacPolicy);
  
  //mock data
  
  const editorUser: User = {
      id: 0,
      roles: ["editor"],
      department: "Marketing"
  };
  
  const privateDoc: Document = {
      id: 100,
      ownerId: 0,
      isPublic: false,
      requiredDepartment: null
  };
  
  const sampleContext: RequestContext = {};
  
  // --- Evaluation ---
  // Editor tries to write to a private doc (Allowed by RBAC)
  let result = await permissionChecker.evaluateAccess({
    subject: editorUser,
    resource: privateDoc,
    action: "write",
    context: sampleContext,
  });
  console.log(`Editor write privateDoc: ${result.isGranted()}`); // Output: true
```

You can add as many policies as you want to a `PermissionChecker` instance. For example, in the code above, you could add a policy to make it so that only users with the `"admin"` role could delete documents.