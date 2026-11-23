import { describe, expect, it } from "@effect/vitest";
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
  it.effect("should grant access when user has required role", () =>
    Effect.gen(function* () {
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

      const result = yield* rbacPolicy.evaluateAccess({
        subject,
        resource,
        action: "read",
        context,
      });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("should deny access when user doesn't have required role", () =>
    Effect.gen(function* () {
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

      const result = yield* rbacPolicy.evaluateAccess({
        subject,
        resource,
        action: "delete",
        context,
      });
      expect(isGranted(result)).toBe(false);
    }),
  );
});

describe("ABAC Policy", () => {
  it.effect("should grant access based on attributes", () =>
    Effect.gen(function* () {
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

      const result = yield* abacPolicy.evaluateAccess({
        subject,
        resource,
        action: "read",
        context,
      });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("should deny access when attributes don't match", () =>
    Effect.gen(function* () {
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

      const result = yield* abacPolicy.evaluateAccess({
        subject,
        resource,
        action: "read",
        context,
      });
      expect(isGranted(result)).toBe(false);
    }),
  );
});

describe("ReBAC Policy", () => {
  it.effect("should grant access based on relationship", () =>
    Effect.gen(function* () {
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
        resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
          subject.id === resource.ownerId,
      });

      const result = yield* rebacPolicy.evaluateAccess({
        subject,
        resource,
        action: "write",
        context,
      });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("should deny access when relationship doesn't exist", () =>
    Effect.gen(function* () {
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
        resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
          subject.id === resource.ownerId,
      });

      const result = yield* rebacPolicy.evaluateAccess({
        subject,
        resource,
        action: "write",
        context,
      });
      expect(isGranted(result)).toBe(false);
    }),
  );
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

  it.effect("AND policy should grant access when all policies grant access", () =>
    Effect.gen(function* () {
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
        resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
          subject.id === resource.ownerId,
      });

      const policy = define.combine(({ and }) => and(rbacPolicy, rebacPolicy));
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("AND policy should deny access when any policy denies access", () =>
    Effect.gen(function* () {
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
        resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
          subject.id === resource.ownerId,
      });

      const policy = define.combine(({ and }) => and(rbacPolicy, rebacPolicy));
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(false);
    }),
  );

  it.effect("OR policy should grant access when any policy grants access", () =>
    Effect.gen(function* () {
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
        resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
          subject.id === resource.ownerId,
      });

      const policy = define.combine(({ or }) => or(rbacPolicy, rebacPolicy));
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("OR policy should deny access when all policies deny access", () =>
    Effect.gen(function* () {
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
        resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
          subject.id === resource.ownerId,
      });

      const nonAdmin: Subject = { ...subject, roles: ["user"] };
      const policy = define.combine(({ or }) => or(rbacPolicy, rebacPolicy));
      const result = yield* policy.evaluateAccess({
        subject: nonAdmin,
        resource,
        action: "admin",
        context,
      });
      expect(isGranted(result)).toBe(false);
    }),
  );

  it.effect("invertPolicy should invert the result", () =>
    Effect.gen(function* () {
      const resource: Resource = {
        id: "resource1",
        ownerId: "user2",
        department: "IT",
        isPublic: true,
      };

      const abacPolicy = define("PublicCheck", {
        resource: (r: Resource) => r.isPublic,
      });

      const normalResult = yield* abacPolicy.evaluateAccess({
        subject,
        resource,
        action: "read",
        context,
      });
      expect(isGranted(normalResult)).toBe(true);

      const notPolicy = invertPolicy(abacPolicy);
      const notResult = yield* notPolicy.evaluateAccess({
        subject,
        resource,
        action: "read",
        context,
      });
      expect(isGranted(notResult)).toBe(false);
    }),
  );
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

  it.effect("should create a policy with subject predicate", () =>
    Effect.gen(function* () {
      const policy = define("AdminOnly", {
        subject: (sub: Subject) => sub.roles.includes("admin"),
      });

      const admin: Subject = {
        id: "user1",
        roles: ["admin"],
        groups: [],
        department: "IT",
      };
      const result = yield* policy.evaluateAccess({
        subject: admin,
        resource,
        action: "read",
        context,
      });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("should create a policy with resource predicate", () =>
    Effect.gen(function* () {
      const policy = define("PublicResourcesOnly", {
        resource: (res) => res.isPublic,
      });

      const result = yield* policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "read",
        context,
      });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("should create a policy with single action literal", () =>
    Effect.gen(function* () {
      const policy = define("ReadOnly", { action: "read" });

      const granted = yield* policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "read",
        context,
      });
      expect(isGranted(granted)).toBe(true);

      const denied = yield* policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "write",
        context,
      });
      expect(isGranted(denied)).toBe(false);
    }),
  );

  it.effect("should create a policy with action array", () =>
    Effect.gen(function* () {
      const policy = define("ReadOrWrite", { action: ["read", "write"] });

      const read = yield* policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "read",
        context,
      });
      expect(isGranted(read)).toBe(true);

      const del = yield* policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "delete",
        context,
      });
      expect(isGranted(del)).toBe(false);
    }),
  );

  it.effect("should create a policy with context predicate", () =>
    Effect.gen(function* () {
      const policy = define("EmergencyOverride", {
        context: (ctx: Context) => ctx.isEmergency,
      });

      const emergencyContext: Context = { ...context, isEmergency: true };
      const result = yield* policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "admin",
        context: emergencyContext,
      });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("should create a policy with multiple conditions", () =>
    Effect.gen(function* () {
      const policy = define("SameDepartmentReadOnly", {
        action: "read",
        when: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
          subject.department === resource.department,
      });

      const result = yield* policy.evaluateAccess({
        subject: { id: "user1", roles: ["user"], groups: [], department: "IT" },
        resource,
        action: "read",
        context,
      });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("should respect deny intent", () =>
    Effect.gen(function* () {
      const policy = define("ExplicitDenyForAdmins", {
        subject: (sub: Subject) => sub.roles.includes("admin"),
        intent: "deny",
      });

      const result = yield* policy.evaluateAccess({
        subject: {
          id: "user1",
          roles: ["admin"],
          groups: [],
          department: "IT",
        },
        resource,
        action: "read",
        context,
      });
      expect(isGranted(result)).toBe(false);
    }),
  );
});

describe("checkPermissions", () => {
  const context: Context = {
    clientIp: "127.0.0.1",
    timestamp: Date.now(),
    isEmergency: false,
  };

  it.effect("should grant access when any policy grants access", () =>
    Effect.gen(function* () {
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
      const result = yield* check({ subject, resource, action: "read", context }).pipe(
        Effect.catch((e) => Effect.succeed(e)),
      );
      expect(result._tag).toBe("AccessGranted");
    }),
  );

  it.effect("should deny access when all policies deny access", () =>
    Effect.gen(function* () {
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
      const result = yield* check({ subject, resource, action: "write", context }).pipe(
        Effect.catch((e) => Effect.succeed(e)),
      );
      expect(result._tag).toBe("AccessDenied");
    }),
  );

  it.effect("should deny access when no policies are configured", () =>
    Effect.gen(function* () {
      const check = checkPermissions<Subject, Resource, Action, Context>([]);
      const result = yield* check({
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
      }).pipe(Effect.catch((e) => Effect.succeed(e)));
      expect(result._tag).toBe("NoPoliciesError");
    }),
  );
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

  it.effect("action as function predicate", () =>
    Effect.gen(function* () {
      const policy = define("CustomActionCheck", {
        action: (a: Action) => a === "read" || a === "write",
      });

      const read = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(read)).toBe(true);

      const del = yield* policy.evaluateAccess({ subject, resource, action: "delete", context });
      expect(isGranted(del)).toBe(false);
    }),
  );

  it.effect("when predicate returning Effect", () =>
    Effect.gen(function* () {
      const policy = define("EffectfulWhen", {
        when: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
          Effect.succeed(subject.department === resource.department),
      });

      const granted = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(granted)).toBe(true);

      const denied = yield* policy.evaluateAccess({
        subject: { ...subject, department: "Sales" },
        resource,
        action: "read",
        context,
      });
      expect(isGranted(denied)).toBe(false);
    }),
  );

  it.effect("mixed plain and Effect predicates in one policy", () =>
    Effect.gen(function* () {
      const policy = define("MixedPredicates", {
        subject: (s: Subject) => s.roles.includes("admin"), // plain boolean
        resource: (r: Resource) => Effect.succeed(r.isPublic), // Effect
        action: "read", // literal
        context: (ctx: Context) => !ctx.isEmergency, // plain boolean
      });

      const granted = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(granted)).toBe(true);
    }),
  );

  it.effect("rbac with effectful userRoles resolver", () =>
    Effect.gen(function* () {
      const policy = define.rbac("EffectfulRbac", {
        roles: {
          read: ["admin"],
          write: ["admin"],
          delete: ["admin"],
          admin: ["admin"],
        },
        userRoles: (s: Subject) => Effect.succeed(s.roles),
      });

      const granted = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(granted)).toBe(true);
    }),
  );

  it.effect("rebac with effectful resolver", () =>
    Effect.gen(function* () {
      const policy = define.rebac("EffectfulRebac", {
        relationship: "owner",
        resolver: ({ subject, resource }: { subject: Subject; resource: Resource }) =>
          Effect.succeed(subject.id === resource.ownerId),
      });

      const granted = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(granted)).toBe(true);
    }),
  );
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

  it.effect("combinePolicy with custom name for and", () =>
    Effect.gen(function* () {
      const policy = define.combine("MyCustomAnd", ({ and }) => and(allow, allow));
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
      expect(policy.name).toBe("MyCustomAnd");
    }),
  );

  it.effect("combinePolicy with custom name for or", () =>
    Effect.gen(function* () {
      const policy = define.combine("MyCustomOr", ({ or }) => or(deny, allow));
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
      expect(policy.name).toBe("MyCustomOr");
    }),
  );

  it.effect("invertPolicy with custom name appears in trace", () =>
    Effect.gen(function* () {
      const policy = invertPolicy("MyCustomNot", deny);
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
      expect(formatResult(result)).toContain("MyCustomNot");
    }),
  );
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

  it.effect("single policy in AND", () =>
    Effect.gen(function* () {
      const policy = define.combine(({ and }) => and(allow));
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("single policy in OR", () =>
    Effect.gen(function* () {
      const policy = define.combine(({ or }) => or(deny));
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(false);
    }),
  );

  it.effect("NOT(NOT(policy)) equals original", () =>
    Effect.gen(function* () {
      const doubleNot = invertPolicy(invertPolicy(allow));
      const result = yield* doubleNot.evaluateAccess({
        subject,
        resource,
        action: "read",
        context,
      });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("intent:deny with non-matching predicates still denies", () =>
    Effect.gen(function* () {
      const policy = define("DenyButNoMatch", {
        subject: (s: Subject) => s.roles.includes("nonexistent"),
        intent: "deny",
      });

      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      // Predicates don't match → DeniedAccessResult("Policy predicate did not match")
      // NOT a grant — deny intent only fires when predicates DO match
      expect(isGranted(result)).toBe(false);
    }),
  );

  it.effect("intent:deny with matching predicates denies", () =>
    Effect.gen(function* () {
      const policy = define("DenyAndMatch", {
        subject: (s: Subject) => s.roles.includes("admin"),
        intent: "deny",
      });

      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(false);
    }),
  );
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

  it.effect("formatResult on granted policy result", () =>
    Effect.gen(function* () {
      const policy = define("GrantPolicy", {});
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      const formatted = formatResult(result);
      expect(formatted).toContain("GrantPolicy");
      expect(formatted).toContain("GRANTED");
    }),
  );

  it.effect("formatResult on denied policy result", () =>
    Effect.gen(function* () {
      const policy = define("DenyPolicy", { subject: () => false });
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      const formatted = formatResult(result);
      expect(formatted).toContain("DenyPolicy");
      expect(formatted).toContain("DENIED");
    }),
  );

  it.effect("formatResult on combined result shows children", () =>
    Effect.gen(function* () {
      const p1 = define("PolicyA", { subject: () => false });
      const p2 = define("PolicyB", {});
      const policy = define.combine("CombinedOr", ({ or }) => or(p1, p2));
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      const formatted = formatResult(result);
      expect(formatted).toContain("PolicyA");
      expect(formatted).toContain("PolicyB");
    }),
  );

  it.effect("getDisplayTrace on AccessGranted", () =>
    Effect.gen(function* () {
      const policy = define("TraceGrant", {});
      const check = checkPermissions([policy]);
      const result = yield* check({ subject, resource, action: "read", context });
      const trace = getDisplayTrace(result);
      expect(trace).toContain("TraceGrant");
      expect(trace).toContain("GRANTED");
    }),
  );

  it.effect("getDisplayTrace on AccessDenied", () =>
    Effect.gen(function* () {
      const policy = define("TraceDeny", { subject: () => false });
      const check = checkPermissions([policy]);
      const result = yield* check({ subject, resource, action: "read", context }).pipe(
        Effect.catch((e) => Effect.succeed(e)),
      );
      const trace = getDisplayTrace(result);
      expect(trace).toContain("TraceDeny");
      expect(trace).toContain("DENIED");
    }),
  );
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

  it.effect("first-grant-wins: stops at first granting policy", () =>
    Effect.gen(function* () {
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
      const result = yield* check({ subject, resource, action: "read", context });

      expect(result._tag).toBe("AccessGranted");
      expect(result.policyType).toBe("Grant");
      expect(thirdPolicyCalled).toBe(false);
    }),
  );

  it.effect("AccessGranted contains correct policyType", () =>
    Effect.gen(function* () {
      const p1 = define("FirstPolicy", { subject: () => false });
      const p2 = define("SecondPolicy", {});

      const check = checkPermissions([p1, p2]);
      const result = yield* check({ subject, resource, action: "read", context });

      expect(result._tag).toBe("AccessGranted");
      expect(result.policyType).toBe("SecondPolicy");
    }),
  );

  it.effect("AccessDenied trace contains all evaluated policies", () =>
    Effect.gen(function* () {
      const p1 = define("PolicyA", { subject: () => false });
      const p2 = define("PolicyB", { subject: () => false });
      const p3 = define("PolicyC", { subject: () => false });

      const check = checkPermissions([p1, p2, p3]);
      const result = yield* check({ subject, resource, action: "read", context }).pipe(
        Effect.catch((e) => Effect.succeed(e)),
      );

      expect(result._tag).toBe("AccessDenied");
      const trace = getDisplayTrace(result);
      expect(trace).toContain("PolicyA");
      expect(trace).toContain("PolicyB");
      expect(trace).toContain("PolicyC");
    }),
  );
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

  it.effect("and combinator grants when all grant", () =>
    Effect.gen(function* () {
      const policy = combinePolicy<Subject, Resource, Action, Context>(({ and }) =>
        and(allow, allow),
      );
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("and combinator denies when any denies", () =>
    Effect.gen(function* () {
      const policy = combinePolicy<Subject, Resource, Action, Context>(({ and }) =>
        and(allow, deny),
      );
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(false);
    }),
  );

  it.effect("or combinator grants when any grants", () =>
    Effect.gen(function* () {
      const policy = combinePolicy<Subject, Resource, Action, Context>(({ or }) => or(deny, allow));
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("not combinator inverts result", () =>
    Effect.gen(function* () {
      const policy = combinePolicy<Subject, Resource, Action, Context>(({ not }) => not(deny));
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("nested composition: and(policy1, or(policy3, not(policy2)))", () =>
    Effect.gen(function* () {
      const policy = combinePolicy<Subject, Resource, Action, Context>(({ and, or, not }) =>
        and(allow, or(deny, not(deny))),
      );
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("named combinePolicy sets policy name", () =>
    Effect.gen(function* () {
      const policy = combinePolicy<Subject, Resource, Action, Context>("MyCombo", ({ and }) =>
        and(allow, allow),
      );
      expect(policy.name).toBe("MyCombo");
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("factory combine method works", () =>
    Effect.gen(function* () {
      const policy = define.combine(({ and, not }) => and(allow, not(deny)));
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it.effect("factory combine with name", () =>
    Effect.gen(function* () {
      const policy = define.combine("FactoryCombo", ({ or }) => or(deny, allow));
      expect(policy.name).toBe("FactoryCombo");
      const result = yield* policy.evaluateAccess({ subject, resource, action: "read", context });
      expect(isGranted(result)).toBe(true);
    }),
  );

  it("auto-generated names use symbolic operators", () => {
    const p1 = define("A", {});
    const p2 = define("B", { intent: "deny" });
    const p3 = define("C", {});

    const policy = combinePolicy<Subject, Resource, Action, Context>(({ and, or, not }) =>
      and(p1, or(p2, not(p3))),
    );
    expect(policy.name).toBe("A & (B | !C)");
  });
});
