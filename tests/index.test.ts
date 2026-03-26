import { describe, test, expect } from "bun:test";
import { Effect, Schema } from "effect";
import {
  checkPermissions,
  combinePolicy,
  formatResult,
  getDisplayTrace,
  invertPolicy,
  isGranted,
  policyFactory,
} from "../src/gatehouse.js";

// Define schemas for testing
const SubjectSchema = Schema.Struct({
  id: Schema.String,
  roles: Schema.Array(Schema.String),
  groups: Schema.Array(Schema.String),
  department: Schema.String,
});

const ResourceSchema = Schema.Struct({
  id: Schema.String,
  ownerId: Schema.String,
  department: Schema.String,
  isPublic: Schema.Boolean,
});

const ActionSchema = Schema.Literals(["read", "write", "delete", "admin"]);

const ContextSchema = Schema.Struct({
  clientIp: Schema.String,
  timestamp: Schema.Number,
  isEmergency: Schema.Boolean,
});

// Infer types from schemas
type Subject = Schema.Schema.Type<typeof SubjectSchema>;
type Resource = Schema.Schema.Type<typeof ResourceSchema>;
type Action = Schema.Schema.Type<typeof ActionSchema>;
type Context = Schema.Schema.Type<typeof ContextSchema>;

// Create the factory — types flow from here
const define = policyFactory({
  subject: SubjectSchema,
  resource: ResourceSchema,
  action: ActionSchema,
  context: ContextSchema,
});

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
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = define.rbac("RbacPolicy", {
      roles: {
        read: ["user", "admin"],
        write: ["editor", "admin"],
        delete: ["admin"],
        admin: ["admin"],
      },
      userRoles: (sub: Subject) => sub.roles,
    });

    const result = await Effect.runPromise(
      rbacPolicy.evaluateAccess({
        subject,
        resource,
        action: "read",
        context,
      }),
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

    const rbacPolicy = define.rbac("RbacPolicy", {
      roles: {
        read: ["user", "admin"],
        write: ["editor", "admin"],
        delete: ["admin"],
        admin: ["admin"],
      },
      userRoles: (sub: Subject) => sub.roles,
    });

    const result = await Effect.runPromise(
      rbacPolicy.evaluateAccess({
        subject,
        resource,
        action: "delete",
        context,
      }),
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
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const abacPolicy = define("AbacPolicy", {
      when: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
        resource.isPublic || subject.department === resource.department,
    });

    const result = await Effect.runPromise(
      abacPolicy.evaluateAccess({
        subject,
        resource,
        action: "read",
        context,
      }),
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
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const abacPolicy = define("AbacPolicy", {
      when: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
        resource.isPublic || subject.department === resource.department,
    });

    const result = await Effect.runPromise(
      abacPolicy.evaluateAccess({
        subject,
        resource,
        action: "read",
        context,
      }),
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
      ownerId: "user1",
      department: "IT",
      isPublic: false,
    };
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rebacPolicy = define.rebac("RebacPolicy", {
      relationship: "owner",
      resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) => subject.id === resource.ownerId,
    });

    const result = await Effect.runPromise(
      rebacPolicy.evaluateAccess({
        subject,
        resource,
        action: "write",
        context,
      }),
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
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rebacPolicy = define.rebac("RebacPolicy", {
      relationship: "owner",
      resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) => subject.id === resource.ownerId,
    });

    const result = await Effect.runPromise(
      rebacPolicy.evaluateAccess({
        subject,
        resource,
        action: "write",
        context,
      }),
    );
    expect(isGranted(result)).toBe(false);
  });
});

describe("Policy Combinators", () => {
  const subject: Subject = {
    id: "user1",
    roles: ["admin"],
    groups: [],
    department: "IT",
  };
  const context: Context = {
    clientIp: "127.0.0.1",
    timestamp: Date.now(),
    isEmergency: false,
  };

  test("AND policy should grant access when all policies grant access", async () => {
    const resource: Resource = {
      id: "resource1",
      ownerId: "user1",
      department: "IT",
      isPublic: true,
    };

    const rbacPolicy = define.rbac("RbacPolicy", {
      roles: {
        read: ["admin", "user"],
        write: ["admin"],
        delete: ["admin"],
        admin: ["admin"],
      },
      userRoles: (sub: Subject) => sub.roles,
    });

    const rebacPolicy = define.rebac("RebacPolicy", {
      relationship: "owner",
      resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) => subject.id === resource.ownerId,
    });

    const policy = define.combine(({ and }) => and(rbacPolicy, rebacPolicy));
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("AND policy should deny access when any policy denies access", async () => {
    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const rbacPolicy = define.rbac("RbacPolicy", {
      roles: {
        read: ["admin", "user"],
        write: ["admin"],
        delete: ["admin"],
        admin: ["admin"],
      },
      userRoles: (sub: Subject) => sub.roles,
    });

    const rebacPolicy = define.rebac("RebacPolicy", {
      relationship: "owner",
      resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) => subject.id === resource.ownerId,
    });

    const policy = define.combine(({ and }) => and(rbacPolicy, rebacPolicy));
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(false);
  });

  test("OR policy should grant access when any policy grants access", async () => {
    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const rbacPolicy = define.rbac("RbacPolicy", {
      roles: {
        read: ["admin", "user"],
        write: ["admin"],
        delete: ["admin"],
        admin: ["admin"],
      },
      userRoles: (sub: Subject) => sub.roles,
    });

    const rebacPolicy = define.rebac("RebacPolicy", {
      relationship: "owner",
      resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) => subject.id === resource.ownerId,
    });

    const policy = define.combine(({ or }) => or(rbacPolicy, rebacPolicy));
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("OR policy should deny access when all policies deny access", async () => {
    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const rbacPolicy = define.rbac("RbacPolicy", {
      roles: {
        read: ["admin", "user"],
        write: ["admin"],
        delete: ["admin"],
        admin: ["admin"],
      },
      userRoles: (sub: Subject) => Effect.succeed(sub.roles),
    });

    const rebacPolicy = define.rebac("RebacPolicy", {
      relationship: "owner",
      resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) => subject.id === resource.ownerId,
    });

    const nonAdmin: Subject = { ...subject, roles: ["user"] };
    const policy = define.combine(({ or }) => or(rbacPolicy, rebacPolicy));
    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: nonAdmin,
        resource,
        action: "admin",
        context,
      }),
    );
    expect(isGranted(result)).toBe(false);
  });

  test("invertPolicy should invert the result", async () => {
    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const abacPolicy = define("PublicCheck", {
      resource: (r: Resource) => r.isPublic,
    });

    const normalResult = await Effect.runPromise(
      abacPolicy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(normalResult)).toBe(true);

    const notPolicy = invertPolicy(abacPolicy);
    const notResult = await Effect.runPromise(
      notPolicy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(notResult)).toBe(false);
  });
});

describe("define (custom policies)", () => {
  const context: Context = {
    clientIp: "127.0.0.1",
    timestamp: Date.now(),
    isEmergency: false,
  };
  const resource: Resource = {
    id: "resource1",
    ownerId: "user2",
    department: "IT",
    isPublic: true,
  };

  test("should create a policy with subject predicate", async () => {
    const policy = define("AdminOnly", {
      subject: (sub: Subject) => sub.roles.includes("admin"),
    });

    const admin: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };
    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: admin,
        resource,
        action: "read",
        context,
      }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("should create a policy with resource predicate", async () => {
    const policy = define("PublicResourcesOnly", {
      resource: (res) => res.isPublic,
    });

    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "read",
        context,
      }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("should create a policy with single action literal", async () => {
    const policy = define("ReadOnly", { action: "read" });

    const granted = await Effect.runPromise(
      policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "read",
        context,
      }),
    );
    expect(isGranted(granted)).toBe(true);

    const denied = await Effect.runPromise(
      policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "write",
        context,
      }),
    );
    expect(isGranted(denied)).toBe(false);
  });

  test("should create a policy with action array", async () => {
    const policy = define("ReadOrWrite", { action: ["read", "write"] });

    const read = await Effect.runPromise(
      policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "read",
        context,
      }),
    );
    expect(isGranted(read)).toBe(true);

    const del = await Effect.runPromise(
      policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "delete",
        context,
      }),
    );
    expect(isGranted(del)).toBe(false);
  });

  test("should create a policy with context predicate", async () => {
    const policy = define("EmergencyOverride", {
      context: (ctx: Context) => ctx.isEmergency,
    });

    const emergencyContext: Context = { ...context, isEmergency: true };
    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "admin",
        context: emergencyContext,
      }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("should create a policy with multiple conditions", async () => {
    const policy = define("SameDepartmentReadOnly", {
      action: "read",
      when: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
        subject.department === resource.department,
    });

    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "read",
        context,
      }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("should respect deny intent", async () => {
    const policy = define("ExplicitDenyForAdmins", {
      subject: (sub: Subject) => sub.roles.includes("admin"),
      intent: "deny",
    });

    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: {
          id: "user1",
          roles: ["admin"],
          groups: [],
          department: "IT",
        },
        resource,
        action: "read",
        context,
      }),
    );
    expect(isGranted(result)).toBe(false);
  });
});

describe("checkPermissions", () => {
  const context: Context = {
    clientIp: "127.0.0.1",
    timestamp: Date.now(),
    isEmergency: false,
  };

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

    const rbacPolicy = define.rbac("RbacPolicy", {
      roles: {
        read: ["admin"],
        write: ["admin"],
        delete: ["admin"],
        admin: ["admin"],
      },
      userRoles: (sub: Subject) => sub.roles,
    });

    const abacPolicy = define("PublicRead", {
      resource: (r: Resource) => r.isPublic,
    });

    const check = checkPermissions([rbacPolicy, abacPolicy]);
    const result = await Effect.runPromise(
      check({ subject, resource, action: "read", context }).pipe(
        Effect.catch((e) => Effect.succeed(e)),
      ),
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

    const rbacPolicy = define.rbac("RbacPolicy", {
      roles: {
        read: ["admin"],
        write: ["admin"],
        delete: ["admin"],
        admin: ["admin"],
      },
      userRoles: (sub: Subject) => sub.roles,
    });

    const abacPolicy = define("DepartmentRead", {
      action: "read",
      when: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
        subject.department === resource.department,
    });

    const check = checkPermissions([rbacPolicy, abacPolicy]);
    const result = await Effect.runPromise(
      check({ subject, resource, action: "write", context }).pipe(
        Effect.catch((e) => Effect.succeed(e)),
      ),
    );
    expect(result._tag).toBe("AccessDenied");
  });

  test("should deny access when no policies are configured", async () => {
    const check = checkPermissions<Subject, Resource, Action, Context>([]);
    const result = await Effect.runPromise(
      check({
        subject: {
          id: "user1",
          roles: ["admin"],
          groups: [],
          department: "IT",
        },
        resource: {
          id: "resource1",
          ownerId: "user1",
          department: "IT",
          isPublic: true,
        },
        action: "read",
        context,
      }).pipe(Effect.catch((e) => Effect.succeed(e))),
    );
    expect(result._tag).toBe("NoPoliciesError");
  });
});

describe("Effectful predicates", () => {
  const subject: Subject = {
    id: "user1",
    roles: ["admin"],
    groups: [],
    department: "IT",
  };
  const resource: Resource = {
    id: "r1",
    ownerId: "user1",
    department: "IT",
    isPublic: true,
  };
  const context: Context = {
    clientIp: "127.0.0.1",
    timestamp: Date.now(),
    isEmergency: false,
  };

  test("action as function predicate", async () => {
    const policy = define("CustomActionCheck", {
      action: (a: Action) => a === "read" || a === "write",
    });

    const read = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(read)).toBe(true);

    const del = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "delete", context }),
    );
    expect(isGranted(del)).toBe(false);
  });

  test("when predicate returning Effect", async () => {
    const policy = define("EffectfulWhen", {
      when: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
        Effect.succeed(subject.department === resource.department),
    });

    const granted = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(granted)).toBe(true);

    const denied = await Effect.runPromise(
      policy.evaluateAccess({
        subject: { ...subject, department: "Sales" },
        resource,
        action: "read",
        context,
      }),
    );
    expect(isGranted(denied)).toBe(false);
  });

  test("mixed plain and Effect predicates in one policy", async () => {
    const policy = define("MixedPredicates", {
      subject: (s: Subject) => s.roles.includes("admin"), // plain boolean
      resource: (r: Resource) => Effect.succeed(r.isPublic), // Effect
      action: "read", // literal
      context: (ctx: Context) => !ctx.isEmergency, // plain boolean
    });

    const granted = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(granted)).toBe(true);
  });

  test("rbac with effectful userRoles resolver", async () => {
    const policy = define.rbac("EffectfulRbac", {
      roles: {
        read: ["admin"],
        write: ["admin"],
        delete: ["admin"],
        admin: ["admin"],
      },
      userRoles: (s: Subject) => Effect.succeed(s.roles),
    });

    const granted = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(granted)).toBe(true);
  });

  test("rebac with effectful resolver", async () => {
    const policy = define.rebac("EffectfulRebac", {
      relationship: "owner",
      resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
        Effect.succeed(subject.id === resource.ownerId),
    });

    const granted = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(granted)).toBe(true);
  });
});

describe("Combinator named overloads", () => {
  const subject: Subject = {
    id: "user1",
    roles: ["admin"],
    groups: [],
    department: "IT",
  };
  const resource: Resource = {
    id: "r1",
    ownerId: "user1",
    department: "IT",
    isPublic: true,
  };
  const context: Context = {
    clientIp: "127.0.0.1",
    timestamp: Date.now(),
    isEmergency: false,
  };

  const allow = define("AllowPolicy", {});
  const deny = define("DenyPolicy", { intent: "deny" });

  test("combinePolicy with custom name for and", async () => {
    const policy = define.combine("MyCustomAnd", ({ and }) =>
      and(allow, allow),
    );
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
    expect(policy.name).toBe("MyCustomAnd");
  });

  test("combinePolicy with custom name for or", async () => {
    const policy = define.combine("MyCustomOr", ({ or }) => or(deny, allow));
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
    expect(policy.name).toBe("MyCustomOr");
  });

  test("invertPolicy with custom name appears in trace", async () => {
    const policy = invertPolicy("MyCustomNot", deny);
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
    expect(formatResult(result)).toContain("MyCustomNot");
  });
});

describe("Edge cases", () => {
  const subject: Subject = {
    id: "user1",
    roles: ["admin"],
    groups: [],
    department: "IT",
  };
  const resource: Resource = {
    id: "r1",
    ownerId: "user1",
    department: "IT",
    isPublic: true,
  };
  const context: Context = {
    clientIp: "127.0.0.1",
    timestamp: Date.now(),
    isEmergency: false,
  };

  const allow = define("AllowPolicy", {});
  const deny = define("DenyPolicy", { intent: "deny" });

  test("single policy in AND", async () => {
    const policy = define.combine(({ and }) => and(allow));
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("single policy in OR", async () => {
    const policy = define.combine(({ or }) => or(deny));
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(false);
  });

  test("NOT(NOT(policy)) equals original", async () => {
    const doubleNot = invertPolicy(invertPolicy(allow));
    const result = await Effect.runPromise(
      doubleNot.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("intent:deny with non-matching predicates still denies", async () => {
    const policy = define("DenyButNoMatch", {
      subject: (s: Subject) => s.roles.includes("nonexistent"),
      intent: "deny",
    });

    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    // Predicates don't match → DeniedAccessResult("Policy predicate did not match")
    // NOT a grant — deny intent only fires when predicates DO match
    expect(isGranted(result)).toBe(false);
  });

  test("intent:deny with matching predicates denies", async () => {
    const policy = define("DenyAndMatch", {
      subject: (s: Subject) => s.roles.includes("admin"),
      intent: "deny",
    });

    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(false);
  });
});

describe("formatResult and getDisplayTrace", () => {
  const subject: Subject = {
    id: "user1",
    roles: ["admin"],
    groups: [],
    department: "IT",
  };
  const resource: Resource = {
    id: "r1",
    ownerId: "user1",
    department: "IT",
    isPublic: true,
  };
  const context: Context = {
    clientIp: "127.0.0.1",
    timestamp: Date.now(),
    isEmergency: false,
  };

  test("formatResult on granted policy result", async () => {
    const policy = define("GrantPolicy", {});
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    const formatted = formatResult(result);
    expect(formatted).toContain("GrantPolicy");
    expect(formatted).toContain("GRANTED");
  });

  test("formatResult on denied policy result", async () => {
    const policy = define("DenyPolicy", { subject: () => false });
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    const formatted = formatResult(result);
    expect(formatted).toContain("DenyPolicy");
    expect(formatted).toContain("DENIED");
  });

  test("formatResult on combined result shows children", async () => {
    const p1 = define("PolicyA", { subject: () => false });
    const p2 = define("PolicyB", {});
    const policy = define.combine("CombinedOr", ({ or }) => or(p1, p2));
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    const formatted = formatResult(result);
    expect(formatted).toContain("PolicyA");
    expect(formatted).toContain("PolicyB");
  });

  test("getDisplayTrace on AccessGranted", async () => {
    const policy = define("TraceGrant", {});
    const check = checkPermissions([policy]);
    const result = await Effect.runPromise(
      check({ subject, resource, action: "read", context }),
    );
    const trace = getDisplayTrace(result);
    expect(trace).toContain("TraceGrant");
    expect(trace).toContain("GRANTED");
  });

  test("getDisplayTrace on AccessDenied", async () => {
    const policy = define("TraceDeny", { subject: () => false });
    const check = checkPermissions([policy]);
    const result = await Effect.runPromise(
      check({ subject, resource, action: "read", context }).pipe(
        Effect.catch((e) => Effect.succeed(e)),
      ),
    );
    const trace = getDisplayTrace(result);
    expect(trace).toContain("TraceDeny");
    expect(trace).toContain("DENIED");
  });
});

describe("checkPermissions ordering and traces", () => {
  const subject: Subject = {
    id: "user1",
    roles: ["admin"],
    groups: [],
    department: "IT",
  };
  const resource: Resource = {
    id: "r1",
    ownerId: "user1",
    department: "IT",
    isPublic: true,
  };
  const context: Context = {
    clientIp: "127.0.0.1",
    timestamp: Date.now(),
    isEmergency: false,
  };

  test("first-grant-wins: stops at first granting policy", async () => {
    let thirdPolicyCalled = false;

    const deny1 = define("Deny1", { subject: () => false });
    const grant = define("Grant", {});
    const spy: typeof grant = {
      name: "SpyPolicy",
      evaluateAccess: (args) => {
        thirdPolicyCalled = true;
        return grant.evaluateAccess(args);
      },
    };

    const check = checkPermissions([deny1, grant, spy]);
    const result = await Effect.runPromise(
      check({ subject, resource, action: "read", context }),
    );

    expect(result._tag).toBe("AccessGranted");
    expect(result.policyType).toBe("Grant");
    expect(thirdPolicyCalled).toBe(false);
  });

  test("AccessGranted contains correct policyType", async () => {
    const p1 = define("FirstPolicy", { subject: () => false });
    const p2 = define("SecondPolicy", {});

    const check = checkPermissions([p1, p2]);
    const result = await Effect.runPromise(
      check({ subject, resource, action: "read", context }),
    );

    expect(result._tag).toBe("AccessGranted");
    expect(result.policyType).toBe("SecondPolicy");
  });

  test("AccessDenied trace contains all evaluated policies", async () => {
    const p1 = define("PolicyA", { subject: () => false });
    const p2 = define("PolicyB", { subject: () => false });
    const p3 = define("PolicyC", { subject: () => false });

    const check = checkPermissions([p1, p2, p3]);
    const result = await Effect.runPromise(
      check({ subject, resource, action: "read", context }).pipe(
        Effect.catch((e) => Effect.succeed(e)),
      ),
    );

    expect(result._tag).toBe("AccessDenied");
    const trace = getDisplayTrace(result);
    expect(trace).toContain("PolicyA");
    expect(trace).toContain("PolicyB");
    expect(trace).toContain("PolicyC");
  });
});

describe("combinePolicy", () => {
  const subject: Subject = {
    id: "user1",
    roles: ["admin"],
    groups: [],
    department: "IT",
  };
  const resource: Resource = {
    id: "r1",
    ownerId: "user1",
    department: "IT",
    isPublic: true,
  };
  const context: Context = {
    clientIp: "127.0.0.1",
    timestamp: Date.now(),
    isEmergency: false,
  };

  const allow = define("AllowPolicy", {});
  const deny = define("DenyPolicy", { intent: "deny" });

  test("and combinator grants when all grant", async () => {
    const policy = combinePolicy<Subject, Resource, Action, Context>(({ and }) => and(allow, allow));
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("and combinator denies when any denies", async () => {
    const policy = combinePolicy<Subject, Resource, Action, Context>(({ and }) => and(allow, deny));
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(false);
  });

  test("or combinator grants when any grants", async () => {
    const policy = combinePolicy<Subject, Resource, Action, Context>(({ or }) => or(deny, allow));
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("not combinator inverts result", async () => {
    const policy = combinePolicy<Subject, Resource, Action, Context>(({ not }) => not(deny));
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("nested composition: and(policy1, or(policy3, not(policy2)))", async () => {
    const policy = combinePolicy<Subject, Resource, Action, Context>(({ and, or, not }) =>
      and(allow, or(deny, not(deny))),
    );
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("named combinePolicy sets policy name", async () => {
    const policy = combinePolicy<Subject, Resource, Action, Context>("MyCombo", ({ and }) => and(allow, allow));
    expect(policy.name).toBe("MyCombo");
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("factory combine method works", async () => {
    const policy = define.combine(({ and, not }) => and(allow, not(deny)));
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("factory combine with name", async () => {
    const policy = define.combine("FactoryCombo", ({ or }) => or(deny, allow));
    expect(policy.name).toBe("FactoryCombo");
    const result = await Effect.runPromise(
      policy.evaluateAccess({ subject, resource, action: "read", context }),
    );
    expect(isGranted(result)).toBe(true);
  });

  test("auto-generated names use symbolic operators", async () => {
    const p1 = define("A", {});
    const p2 = define("B", { intent: "deny" });
    const p3 = define("C", {});

    const policy = combinePolicy<Subject, Resource, Action, Context>(({ and, or, not }) =>
      and(p1, or(p2, not(p3))),
    );
    expect(policy.name).toBe("A & (B | !C)");
  });
});
