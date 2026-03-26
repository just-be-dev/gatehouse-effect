import { describe, test, expect, beforeEach } from "bun:test";
import { Effect, Schema } from "effect";
import {
  AccessDenied,
  AccessGranted,
  checkPermissions,
  combinePolicy,
  DeniedAccessResult,
  formatResult,
  getDisplayTrace,
  GrantedAccessResult,
  invertPolicy,
  isGranted,
  NoPoliciesError,
  policyFactory,
  type Policy,
} from "../src/gatehouse.js";

type CheckResult = AccessGranted | AccessDenied | NoPoliciesError;

type TestSubject = {
  id: string;
};

type TestResource = {
  id: string;
};

type TestAction = Record<string, never>; // Empty object type
const testAction: TestAction = {}; // Singleton instance

type TestContext = Record<string, never>; // Empty object type
const testContext: TestContext = {}; // Singleton instance

const newId = () => Bun.randomUUIDv7();

// AlwaysAllowPolicy
const alwaysAllowPolicy: Policy<
  TestSubject,
  TestResource,
  TestAction,
  TestContext
> = {
  name: "AlwaysAllowPolicy",
  evaluateAccess: () =>
    Effect.succeed(
      new GrantedAccessResult({
        policyType: "AlwaysAllowPolicy",
        reason: "Always allow policy",
      })
    ),
};

// AlwaysDenyPolicy
function buildAlwaysDenyPolicy(
  reason: string
): Policy<TestSubject, TestResource, TestAction, TestContext> {
  const name = "AlwaysDenyPolicy";
  return {
    name,
    evaluateAccess: () =>
      Effect.succeed(
        new DeniedAccessResult({
          policyType: name,
          reason: reason,
        })
      ),
  };
}

// Dummy Relationship Resolver for ReBAC tests
type RelationshipTuple = [
  subjectId: string,
  resourceId: string,
  relationship: string
];

class DummyRelationshipResolver {
  private relationships: RelationshipTuple[];

  constructor(relationships: RelationshipTuple[] = []) {
    this.relationships = relationships;
  }

  hasRelationship({
    subject,
    resource,
    relationship,
  }: {
    subject: TestSubject;
    resource: TestResource;
    relationship: string;
  }): Effect.Effect<boolean> {
    return Effect.succeed(
      this.relationships.some(
        ([sId, rId, rel]) =>
          sId === subject.id && rId === resource.id && rel === relationship
      )
    );
  }
}

describe("Original Test Suite", () => {
  let check: ReturnType<typeof checkPermissions<TestSubject, TestResource, TestAction, TestContext>>;
  let subject: TestSubject;
  let resource: TestResource;

  beforeEach(() => {
    check = checkPermissions([]);
    subject = { id: newId() };
    resource = { id: newId() };
  });

  test("No Policies", async () => {
    const result: CheckResult = await Effect.runPromise(
      check({
        subject,
        resource,
        action: testAction,
        context: testContext,
      }).pipe(Effect.catch((e) => Effect.succeed(e)))
    );

    expect(result._tag).toBe("NoPoliciesError");

    const traceStr = getDisplayTrace(result);
    expect(traceStr).toContain("No policies configured");
  });

  test("One Policy Allow", async () => {
    check = checkPermissions([alwaysAllowPolicy]);
    const result: CheckResult = await Effect.runPromise(
      check({
        subject,
        resource,
        action: testAction,
        context: testContext,
      }).pipe(Effect.catch((e) => Effect.succeed(e)))
    );

    expect(result._tag).toBe("AccessGranted");
    const traceStr = getDisplayTrace(result);
    expect(traceStr).toContain("AlwaysAllowPolicy");
  });

  test("One Policy Deny", async () => {
    const denyReason = "DeniedByPolicy";
    check = checkPermissions([buildAlwaysDenyPolicy(denyReason)]);
    const result: CheckResult = await Effect.runPromise(
      check({
        subject,
        resource,
        action: testAction,
        context: testContext,
      }).pipe(Effect.catch((e) => Effect.succeed(e)))
    );

    expect(result._tag).toBe("AccessDenied");
    const traceStr = getDisplayTrace(result);
    expect(traceStr).toContain("AlwaysDenyPolicy");
    expect(traceStr).toContain(denyReason);
  });

  test("Multiple Policies Or Success", async () => {
    check = checkPermissions([
      buildAlwaysDenyPolicy("DenyPolicy"),
      alwaysAllowPolicy,
    ]);

    const result: CheckResult = await Effect.runPromise(
      check({
        subject,
        resource,
        action: testAction,
        context: testContext,
      }).pipe(Effect.catch((e) => Effect.succeed(e)))
    );

    expect(result._tag).toBe("AccessGranted");
    const traceStr = getDisplayTrace(result);
    expect(traceStr).toContain("AlwaysAllowPolicy");
    expect(traceStr).toContain("DenyPolicy");
  });

  test("Multiple Policies All Deny Collect Reasons", async () => {
    check = checkPermissions([
      buildAlwaysDenyPolicy("DenyPolicy1"),
      buildAlwaysDenyPolicy("DenyPolicy2"),
    ]);

    const result: CheckResult = await Effect.runPromise(
      check({
        subject,
        resource,
        action: testAction,
        context: testContext,
      }).pipe(Effect.catch((e) => Effect.succeed(e)))
    );

    expect(result._tag).toBe("AccessDenied");
    const traceStr = getDisplayTrace(result);
    expect(traceStr).toContain("AlwaysDenyPolicy");
    expect(traceStr).toContain("DenyPolicy1");
    expect(traceStr).toContain("DenyPolicy2");
  });

  // --- RebacPolicy Tests ---
  describe("ReBAC Policy", () => {
    const define = policyFactory({
      subject: Schema.Struct({ id: Schema.String }),
      resource: Schema.Struct({ id: Schema.String }),
      action: Schema.Unknown,
      context: Schema.Unknown,
    });

    test("ReBAC Policy Allows When Relationship Exists", async () => {
      const subjectId = newId();
      const resourceId = newId();
      const relationship = "manager";

      const currentSubject = { id: subjectId };
      const currentResource = { id: resourceId };

      const resolver = new DummyRelationshipResolver([
        [subjectId, resourceId, relationship],
      ]);
      const policy = define.rebac("RebacPolicy", {
        relationship,
        resolver: ({ subject, resource }: { subject: TestSubject; resource: TestResource }) =>
          resolver.hasRelationship({ subject, resource, relationship }),
      });

      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject: currentSubject,
          resource: currentResource,
          action: testAction,
          context: testContext,
        })
      );
      expect(isGranted(result)).toBe(true);
    });

    test("ReBAC Policy Denies When Relationship Missing", async () => {
      const subjectId = newId();
      const resourceId = newId();
      const relationship = "manager";

      const currentSubject = { id: subjectId };
      const currentResource = { id: resourceId };

      const resolver = new DummyRelationshipResolver([]);
      const policy = define.rebac("RebacPolicy", {
        relationship,
        resolver: ({ subject, resource }: { subject: TestSubject; resource: TestResource }) =>
          resolver.hasRelationship({ subject, resource, relationship }),
      });

      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject: currentSubject,
          resource: currentResource,
          action: testAction,
          context: testContext,
        })
      );
      expect(isGranted(result)).toBe(false);
    });
  });

  // --- Combinator Tests ---
  describe("Combinators", () => {
    test("And Policy Allows When All Allow", async () => {
      const policy = combinePolicy<TestSubject, TestResource, TestAction, TestContext>(({ and }) => and(alwaysAllowPolicy, alwaysAllowPolicy));
      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(isGranted(result)).toBe(true);
    });

    test("And Policy Denies When One Denies", async () => {
      const denyReason = "DenyInAnd";
      const policy = combinePolicy<TestSubject, TestResource, TestAction, TestContext>(({ and }) => and(alwaysAllowPolicy, buildAlwaysDenyPolicy(denyReason)));
      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(isGranted(result)).toBe(false);
      const traceStr = formatResult(result);
      expect(traceStr).toContain("&");
      expect(traceStr).toContain(denyReason);
    });

    test("Or Policy Allows When One Allows", async () => {
      const policy = combinePolicy<TestSubject, TestResource, TestAction, TestContext>(({ or }) => or(buildAlwaysDenyPolicy("Deny1"), alwaysAllowPolicy));
      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(isGranted(result)).toBe(true);
    });

    test("Or Policy Denies When All Deny", async () => {
      const policy = combinePolicy<TestSubject, TestResource, TestAction, TestContext>(({ or }) => or(
        buildAlwaysDenyPolicy("Deny1"),
        buildAlwaysDenyPolicy("Deny2"),
      ));
      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(isGranted(result)).toBe(false);
      const traceStr = formatResult(result);
      expect(traceStr).toContain("|");
      expect(traceStr).toContain("Deny1");
      expect(traceStr).toContain("Deny2");
    });

    test("Not Policy Allows When Inner Denies", async () => {
      const policy = invertPolicy(buildAlwaysDenyPolicy("AlwaysDeny"));
      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(isGranted(result)).toBe(true);
    });

    test("Not Policy Denies When Inner Allows", async () => {
      const policy = invertPolicy(alwaysAllowPolicy);
      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(isGranted(result)).toBe(false);
      const traceStr = formatResult(result);
      expect(traceStr).toContain("!");
      expect(traceStr).toContain("AlwaysAllowPolicy");
    });

    test("Deeply Nested Combinators", async () => {
      /*
        This is a more complex example that tests the nesting and evaluation order of the policies.
            NOT(AND(Allow, OR(Deny, NOT(Deny))))
        */
      const innerDeny = buildAlwaysDenyPolicy("InnerDeny");
      const midDeny = buildAlwaysDenyPolicy("MidDeny");

      const outerNot = combinePolicy<TestSubject, TestResource, TestAction, TestContext>(({ and, or, not }) =>
        not(and(alwaysAllowPolicy, or(midDeny, not(innerDeny))))
      );

      const result = await Effect.runPromise(
        outerNot.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );

      expect(isGranted(result)).toBe(false);

      // Verify the correct structure of the trace
      const traceStr = formatResult(result);
      expect(traceStr).toContain("!"); // Outer NOT
      expect(traceStr).toContain("&"); // Inner AND
      expect(traceStr).toContain("|"); // Inner OR
      expect(traceStr).toContain("InnerDeny"); // Innermost Deny
      expect(traceStr).toContain("MidDeny"); // Other deny in OR
      expect(traceStr).toContain("AlwaysAllowPolicy"); // Allow in AND
    });
  });

  // --- Context-sensitive policy test ---
  describe("Context Sensitive Policy", () => {
    type FeatureFlagContext = {
      featureEnabled: boolean;
    };

    const featureFlagPolicy: Policy<
      TestSubject,
      TestResource,
      TestAction,
      FeatureFlagContext
    > = {
      name: "FeatureFlagPolicy",
      evaluateAccess: ({ context }: { subject: TestSubject; resource: TestResource; action: TestAction; context: FeatureFlagContext }) => {
        if (context.featureEnabled) {
          return Effect.succeed(
            new GrantedAccessResult({
              policyType: "FeatureFlagPolicy",
              reason: "Feature flag enabled",
            })
          );
        } else {
          return Effect.succeed(
            new DeniedAccessResult({
              policyType: "FeatureFlagPolicy",
              reason: "Feature flag disabled",
            })
          );
        }
      },
    };

    test("Context Sensitive Policy", async () => {
      const contextEnabled: FeatureFlagContext = { featureEnabled: true };
      let result = await Effect.runPromise(
        featureFlagPolicy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: contextEnabled,
        })
      );
      expect(isGranted(result)).toBe(true);

      const contextDisabled: FeatureFlagContext = { featureEnabled: false };
      result = await Effect.runPromise(
        featureFlagPolicy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: contextDisabled,
        })
      );
      expect(isGranted(result)).toBe(false);
    });
  });

  describe("Short Circuit Evaluation", () => {
    let evaluationCount = 0;

    function buildCountingPolicy(
      resultToReturn: boolean
    ): Policy<TestSubject, TestResource, TestAction, TestContext> {
      const name = `CountingPolicy(${resultToReturn ? "Allow" : "Deny"})`;
      return {
        name: name,
        evaluateAccess: () =>
          Effect.sync(() => {
            evaluationCount++;
            if (resultToReturn) {
              return new GrantedAccessResult({
                policyType: name,
                reason: "Counting policy granted",
              });
            } else {
              return new DeniedAccessResult({
                policyType: name,
                reason: "Counting policy denied",
              });
            }
          }),
      };
    }

    beforeEach(() => {
      evaluationCount = 0; // Reset counter before each short-circuit test
    });

    test("AND policy should short-circuit after first deny", async () => {
      const policy = combinePolicy<TestSubject, TestResource, TestAction, TestContext>(({ and }) => and(
        buildCountingPolicy(false), // Denies, should cause short-circuit
        buildCountingPolicy(true), // Allows, should not be evaluated
      ));
      await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(evaluationCount).toBe(1);
    });

    test("OR policy should short-circuit after first allow", async () => {
      const policy = combinePolicy<TestSubject, TestResource, TestAction, TestContext>(({ or }) => or(
        buildCountingPolicy(true), // Allows, should cause short-circuit
        buildCountingPolicy(false), // Denies, should not be evaluated
      ));
      await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(evaluationCount).toBe(1);
    });
  });
});

// --- policyFactory define() Tests ---
describe("define (custom policies)", () => {
  const builderSubjectAlice = { name: "Alice" };
  const builderSubjectBob = { name: "Bob" };
  const builderSubjectAny = { name: "Any" };

  const define = policyFactory({
    subject: Schema.Struct({ name: Schema.String }),
    resource: Schema.Struct({ id: Schema.String }),
    action: Schema.Unknown,
    context: Schema.Unknown,
  });

  test("Policy Allows When No Predicates", async () => {
    const policy = define("NoPredicatesPolicy");

    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: builderSubjectAny,
        action: testAction,
        resource: { id: newId() },
        context: testContext,
      })
    );
    expect(isGranted(result)).toBe(true);
  });

  test("Policy With Subject Predicate", async () => {
    const policy = define("SubjectPolicy", {
      subject: (s: { readonly name: string }) => s.name === "Alice",
    });

    let result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: builderSubjectAlice,
        action: testAction,
        resource: { id: newId() },
        context: testContext,
      })
    );
    expect(isGranted(result)).toBe(true);

    result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: builderSubjectBob,
        action: testAction,
        resource: { id: newId() },
        context: testContext,
      })
    );
    expect(isGranted(result)).toBe(false);
  });

  test("Policy With Deny Intent", async () => {
    const policy = define("DenyPolicy", { intent: "deny" });

    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: builderSubjectAny,
        action: testAction,
        resource: { id: newId() },
        context: testContext,
      })
    );
    expect(isGranted(result)).toBe(false);
  });

  test("Policy With Extra Condition", async () => {
    const extDefine = policyFactory({
      subject: Schema.Struct({ id: Schema.String, name: Schema.String }),
      resource: Schema.Struct({ ownerId: Schema.String }),
      action: Schema.Unknown,
      context: Schema.Unknown,
    });

    const subjectId = newId();
    const aliceOwnerSubject = { id: subjectId, name: "Alice" };
    const resourceOwnedByAlice = { ownerId: subjectId };
    const resourceOwnedByOther = { ownerId: newId() };

    const policy = extDefine("AliceOwnerPolicy", {
      subject: (s: { readonly id: string; readonly name: string }) => s.name === "Alice",
      when: ({ subject, resource }: { subject: { readonly id: string; readonly name: string }; resource: { readonly ownerId: string } }) => subject.id === resource.ownerId,
    });

    // Both conditions met
    let result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: aliceOwnerSubject,
        action: testAction,
        resource: resourceOwnedByAlice,
        context: testContext,
      })
    );
    expect(isGranted(result)).toBe(true);

    // Extra condition fails
    result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: aliceOwnerSubject,
        action: testAction,
        resource: resourceOwnedByOther,
        context: testContext,
      })
    );
    expect(isGranted(result)).toBe(false);

    // Subject condition fails
    result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: { id: subjectId, name: "Bob" },
        action: testAction,
        resource: resourceOwnedByAlice,
        context: testContext,
      })
    );
    expect(isGranted(result)).toBe(false);
  });
});
