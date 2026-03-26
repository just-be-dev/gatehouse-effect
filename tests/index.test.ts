import { describe, test, expect } from "bun:test";
import { Effect } from "effect";
import {
  buildAbacPolicy,
  buildAndPolicy,
  buildNotPolicy,
  buildOrPolicy,
  buildRbacPolicy,
  buildRebacPolicy,
  checkPermissions,
  isGranted,
  makePolicy,
} from "../src/gatehouse";

// Define types for testing
type Subject = {
  id: string;
  roles: string[];
  groups: string[];
  department: string;
};

type Resource = {
  id: string;
  ownerId: string;
  department: string;
  isPublic: boolean;
};

type Action = "read" | "write" | "delete" | "admin";

type Context = {
  clientIp: string;
  timestamp: number;
  isEmergency: boolean;
};

describe("RBAC Policy", () => {
  test("should grant access when user has required role", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: (_, act) => {
        if (act === "read") return Effect.succeed(["user", "admin"]);
        if (act === "write") return Effect.succeed(["editor", "admin"]);
        if (act === "delete") return Effect.succeed(["admin"]);
        return Effect.succeed(["admin"]);
      },
      userRolesResolver: (sub) => Effect.succeed(sub.roles),
    });

    const result = await Effect.runPromise(
      rbacPolicy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(true);
  });

  test("should deny access when user doesn't have required role", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const action: Action = "delete";
    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: (_, act) => {
        if (act === "read") return Effect.succeed(["user", "admin"]);
        if (act === "write") return Effect.succeed(["editor", "admin"]);
        if (act === "delete") return Effect.succeed(["admin"]);
        return Effect.succeed(["admin"]);
      },
      userRolesResolver: (sub) => Effect.succeed(sub.roles),
    });

    const result = await Effect.runPromise(
      rbacPolicy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(false);
  });
});

describe("ABAC Policy", () => {
  test("should grant access based on attributes", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const abacPolicy = buildAbacPolicy<Subject, Resource, Action, Context>({
      condition: ({ subject, resource }) =>
        Effect.succeed(
          resource.isPublic || subject.department === resource.department
        ),
    });

    const result = await Effect.runPromise(
      abacPolicy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(true);
  });

  test("should deny access when attributes don't match", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "Sales",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const abacPolicy = buildAbacPolicy<Subject, Resource, Action, Context>({
      condition: ({ subject, resource }) =>
        Effect.succeed(
          resource.isPublic || subject.department === resource.department
        ),
    });

    const result = await Effect.runPromise(
      abacPolicy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(false);
  });
});

describe("ReBAC Policy", () => {
  test("should grant access based on relationship", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user1", // Note: same as subject id
      department: "IT",
      isPublic: false,
    };

    const action: Action = "write";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rebacPolicy = buildRebacPolicy<Subject, Resource, Action, Context>({
      relationship: "owner",
      resolver: ({ subject, resource }) =>
        Effect.succeed(subject.id === resource.ownerId),
    });

    const result = await Effect.runPromise(
      rebacPolicy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(true);
  });

  test("should deny access when relationship doesn't exist", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2", // Note: different from subject id
      department: "IT",
      isPublic: false,
    };

    const action: Action = "write";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rebacPolicy = buildRebacPolicy<Subject, Resource, Action, Context>({
      relationship: "owner",
      resolver: ({ subject, resource }) =>
        Effect.succeed(subject.id === resource.ownerId),
    });

    const result = await Effect.runPromise(
      rebacPolicy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(false);
  });
});

describe("Policy Combinators", () => {
  test("AND policy should grant access when all policies grant access", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user1",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: () => Effect.succeed(["admin", "user"]),
      userRolesResolver: (sub) => Effect.succeed(sub.roles),
    });

    const rebacPolicy = buildRebacPolicy<Subject, Resource, Action, Context>({
      relationship: "owner",
      resolver: ({ subject, resource }) =>
        Effect.succeed(subject.id === resource.ownerId),
    });

    const andPolicy = buildAndPolicy({
      policies: [rbacPolicy, rebacPolicy],
    });
    const result = await Effect.runPromise(
      andPolicy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(true);
  });

  test("AND policy should deny access when any policy denies access", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2", // Not the owner
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: () => Effect.succeed(["admin", "user"]),
      userRolesResolver: (sub) => Effect.succeed(sub.roles),
    });

    const rebacPolicy = buildRebacPolicy<Subject, Resource, Action, Context>({
      relationship: "owner",
      resolver: ({ subject, resource }) =>
        Effect.succeed(subject.id === resource.ownerId),
    });

    const andPolicy = buildAndPolicy({
      policies: [rbacPolicy, rebacPolicy],
    });
    const result = await Effect.runPromise(
      andPolicy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(false);
  });

  test("OR policy should grant access when any policy grants access", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2", // Not the owner
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: () => Effect.succeed(["admin", "user"]),
      userRolesResolver: (sub) => Effect.succeed(sub.roles),
    });

    const rebacPolicy = buildRebacPolicy<Subject, Resource, Action, Context>({
      relationship: "owner",
      resolver: ({ subject, resource }) =>
        Effect.succeed(subject.id === resource.ownerId),
    });

    const orPolicy = buildOrPolicy({
      policies: [rbacPolicy, rebacPolicy],
    });
    const result = await Effect.runPromise(
      orPolicy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(true);
  });

  test("OR policy should deny access when all policies deny access", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"], // Not admin
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2", // Not the owner
      department: "IT",
      isPublic: true,
    };

    const action: Action = "admin"; // Requires admin role
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: (_, act) =>
        Effect.succeed(act === "admin" ? ["admin"] : ["user"]),
      userRolesResolver: (sub) => Effect.succeed(sub.roles),
    });

    const rebacPolicy = buildRebacPolicy<Subject, Resource, Action, Context>({
      relationship: "owner",
      resolver: ({ subject, resource }) =>
        Effect.succeed(subject.id === resource.ownerId),
    });

    const orPolicy = buildOrPolicy({
      policies: [rbacPolicy, rebacPolicy],
    });
    const result = await Effect.runPromise(
      orPolicy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(false);
  });

  test("NOT policy should invert the result", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const abacPolicy = buildAbacPolicy<Subject, Resource, Action, Context>({
      condition: ({ resource }) => Effect.succeed(resource.isPublic),
    });

    // This would normally grant access since resource is public
    const normalResult = await Effect.runPromise(
      abacPolicy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(normalResult)).toBe(true);

    // But the NOT policy inverts it
    const notPolicy = buildNotPolicy({
      policy: abacPolicy,
    });
    const notResult = await Effect.runPromise(
      notPolicy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(notResult)).toBe(false);
  });
});

describe("makePolicy", () => {
  test("should create a policy with subjects condition", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const policy = makePolicy<Subject, Resource, Action, Context>("AdminOnly", {
      subject: (sub) => Effect.succeed(sub.roles.includes("admin")),
    });

    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(true);
  });

  test("should create a policy with resources condition", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const policy = makePolicy<Subject, Resource, Action, Context>(
      "PublicResourcesOnly",
      {
        resource: (res) => Effect.succeed(res.isPublic),
      },
    );

    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(true);
  });

  test("should create a policy with action condition", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const policy = makePolicy<Subject, Resource, Action, Context>("ReadOnly", {
      action: (act) => Effect.succeed(act === "read"),
    });

    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(true);
  });

  test("should create a policy with context condition", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const action: Action = "admin";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: true, // Emergency override
    };

    const policy = makePolicy<Subject, Resource, Action, Context>(
      "EmergencyOverride",
      {
        context: (ctx) => Effect.succeed(ctx.isEmergency),
      },
    );

    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(true);
  });

  test("should create a policy with multiple conditions", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const policy = makePolicy<Subject, Resource, Action, Context>(
      "SameDepartmentReadOnly",
      {
        action: (act) => Effect.succeed(act === "read"),
        when: ({ subject, resource }) =>
          Effect.succeed(subject.department === resource.department),
      },
    );

    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(true);
  });

  test("should respect deny effect", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const policy = makePolicy<Subject, Resource, Action, Context>(
      "ExplicitDenyForAdmins",
      {
        subject: (sub) => Effect.succeed(sub.roles.includes("admin")),
        intent: 'deny',
      },
    );

    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      })
    );
    expect(isGranted(result)).toBe(false);
  });
});

describe("checkPermissions", () => {
  test("should grant access when any policy grants access", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: () => Effect.succeed(["admin"]),
      userRolesResolver: (sub) => Effect.succeed(sub.roles),
    });

    const abacPolicy = buildAbacPolicy<Subject, Resource, Action, Context>({
      condition: ({ resource }) => Effect.succeed(resource.isPublic),
    });

    const check = checkPermissions([rbacPolicy, abacPolicy]);

    const result = await Effect.runPromise(
      check({
        subject,
        resource,
        action,
        context,
      }).pipe(Effect.catch((e) => Effect.succeed(e)))
    );
    expect(result._tag).toBe("AccessGranted");
  });

  test("should deny access when all policies deny access", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "Sales",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const action: Action = "write";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: () => Effect.succeed(["admin"]),
      userRolesResolver: (sub) => Effect.succeed(sub.roles),
    });

    const abacPolicy = buildAbacPolicy<Subject, Resource, Action, Context>({
      condition: ({ subject, resource, action }) =>
        Effect.succeed(
          subject.department === resource.department && action === "read"
        ),
    });

    const check = checkPermissions([rbacPolicy, abacPolicy]);

    const result = await Effect.runPromise(
      check({
        subject,
        resource,
        action,
        context,
      }).pipe(Effect.catch((e) => Effect.succeed(e)))
    );
    expect(result._tag).toBe("AccessDenied");
  });

  test("should deny access when no policies are configured", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user1",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const check = checkPermissions<Subject, Resource, Action, Context>([]);
    const result = await Effect.runPromise(
      check({
        subject,
        resource,
        action,
        context,
      }).pipe(Effect.catch((e) => Effect.succeed(e)))
    );
    expect(result._tag).toBe("NoPoliciesError");
  });
});
