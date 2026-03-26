import { describe, test, expect, beforeEach } from "bun:test";
import { Effect } from "effect";
import {
  buildAndPolicy,
  buildNotPolicy,
  buildOrPolicy,
  buildRebacPolicy,
  PermissionChecker,
  PolicyBuilder,
  type Policy,
  type PolicyEvalResult,
  PolicyEffect,
} from "../src/gatehouse";

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
    Effect.succeed({
      policyType: "AlwaysAllowPolicy",
      reason: "Always allow policy",
      isGranted: () => true,
      format: () => "\u2714 AlwaysAllowPolicy GRANTED Always allow policy",
    }),
};

// AlwaysDenyPolicy
function buildAlwaysDenyPolicy(
  reason: string
): Policy<TestSubject, TestResource, TestAction, TestContext> {
  const name = "AlwaysDenyPolicy";
  return {
    name,
    evaluateAccess: () =>
      Effect.succeed({
        policyType: name,
        reason: reason,
        isGranted: () => false,
        format: () => `\u2718 ${name} DENIED: ${reason}`,
      }),
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
  let checker: PermissionChecker<
    TestSubject,
    TestResource,
    TestAction,
    TestContext
  >;
  let subject: TestSubject;
  let resource: TestResource;

  beforeEach(() => {
    checker = new PermissionChecker();
    subject = { id: newId() };
    resource = { id: newId() };
  });

  test("No Policies", async () => {
    const result = await Effect.runPromise(
      checker
        .evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
        .pipe(Effect.catch((e) => Effect.succeed(e)))
    );

    expect(result.isGranted()).toBe(false);

    const traceStr = result.getDisplayTrace();
    expect(traceStr).toContain("No policies configured");
  });

  test("One Policy Allow", async () => {
    checker.addPolicy(alwaysAllowPolicy);
    const result = await Effect.runPromise(
      checker
        .evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
        .pipe(Effect.catch((e) => Effect.succeed(e)))
    );

    expect(result.isGranted()).toBe(true);
    const traceStr = result.getDisplayTrace();
    expect(traceStr).toContain("AlwaysAllowPolicy");
  });

  test("One Policy Deny", async () => {
    const denyReason = "DeniedByPolicy";
    checker.addPolicy(buildAlwaysDenyPolicy(denyReason));
    const result = await Effect.runPromise(
      checker
        .evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
        .pipe(Effect.catch((e) => Effect.succeed(e)))
    );

    expect(result.isGranted()).toBe(false);
    const traceStr = result.getDisplayTrace();
    expect(traceStr).toContain("AlwaysDenyPolicy");
    expect(traceStr).toContain(denyReason);
  });

  test("Multiple Policies Or Success", async () => {
    checker.addPolicy(buildAlwaysDenyPolicy("DenyPolicy"));
    checker.addPolicy(alwaysAllowPolicy);

    const result = await Effect.runPromise(
      checker
        .evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
        .pipe(Effect.catch((e) => Effect.succeed(e)))
    );

    expect(result.isGranted()).toBe(true);
    const traceStr = result.getDisplayTrace();
    expect(traceStr).toContain("AlwaysAllowPolicy");
    expect(traceStr).toContain("DenyPolicy");
  });

  test("Multiple Policies All Deny Collect Reasons", async () => {
    checker.addPolicy(buildAlwaysDenyPolicy("DenyPolicy1"));
    checker.addPolicy(buildAlwaysDenyPolicy("DenyPolicy2"));

    const result = await Effect.runPromise(
      checker
        .evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
        .pipe(Effect.catch((e) => Effect.succeed(e)))
    );

    expect(result.isGranted()).toBe(false);
    const traceStr = result.getDisplayTrace();
    expect(traceStr).toContain("AlwaysDenyPolicy");
    expect(traceStr).toContain("DenyPolicy1");
    expect(traceStr).toContain("DenyPolicy2");
  });

  // --- RebacPolicy Tests ---
  describe("ReBAC Policy", () => {
    test("ReBAC Policy Allows When Relationship Exists", async () => {
      const subjectId = newId();
      const resourceId = newId();
      const relationship = "manager";

      const currentSubject = { id: subjectId };
      const currentResource = { id: resourceId };

      const resolver = new DummyRelationshipResolver([
        [subjectId, resourceId, relationship],
      ]);
      const policy = buildRebacPolicy<
        TestSubject,
        TestResource,
        TestAction,
        TestContext
      >({
        relationship: relationship,
        resolver: ({ subject, resource, relationship }) =>
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
      expect(result.isGranted()).toBe(true);
    });

    test("ReBAC Policy Denies When Relationship Missing", async () => {
      const subjectId = newId();
      const resourceId = newId();
      const relationship = "manager";

      const currentSubject = { id: subjectId };
      const currentResource = { id: resourceId };

      const resolver = new DummyRelationshipResolver([]); // Empty relationships
      const policy = buildRebacPolicy<
        TestSubject,
        TestResource,
        TestAction,
        TestContext
      >({
        relationship,
        resolver: ({ subject, resource, relationship }) =>
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
      expect(result.isGranted()).toBe(false);
    });
  });

  // --- Combinator Tests ---
  describe("Combinators", () => {
    test("And Policy Allows When All Allow", async () => {
      const policy = buildAndPolicy({
        policies: [alwaysAllowPolicy, alwaysAllowPolicy],
      });
      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(result.isGranted()).toBe(true);
    });

    test("And Policy Denies When One Denies", async () => {
      const denyReason = "DenyInAnd";
      const policy = buildAndPolicy({
        policies: [alwaysAllowPolicy, buildAlwaysDenyPolicy(denyReason)],
      });
      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(result.isGranted()).toBe(false);
      const traceStr = result.format();
      expect(traceStr).toContain("AndPolicy");
      expect(traceStr).toContain(denyReason);
    });

    test("Or Policy Allows When One Allows", async () => {
      const policy = buildOrPolicy({
        policies: [buildAlwaysDenyPolicy("Deny1"), alwaysAllowPolicy],
      });
      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(result.isGranted()).toBe(true);
    });

    test("Or Policy Denies When All Deny", async () => {
      const policy = buildOrPolicy({
        policies: [
          buildAlwaysDenyPolicy("Deny1"),
          buildAlwaysDenyPolicy("Deny2"),
        ],
      });
      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(result.isGranted()).toBe(false);
      const traceStr = result.format();
      expect(traceStr).toContain("OrPolicy");
      expect(traceStr).toContain("Deny1");
      expect(traceStr).toContain("Deny2");
    });

    test("Not Policy Allows When Inner Denies", async () => {
      const policy = buildNotPolicy({
        policy: buildAlwaysDenyPolicy("AlwaysDeny"),
      });
      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(result.isGranted()).toBe(true);
    });

    test("Not Policy Denies When Inner Allows", async () => {
      const policy = buildNotPolicy({ policy: alwaysAllowPolicy });
      const result = await Effect.runPromise(
        policy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(result.isGranted()).toBe(false);
      const traceStr = result.format();
      expect(traceStr).toContain("NotPolicy");
      expect(traceStr).toContain("AlwaysAllowPolicy");
    });

    test("Empty Policies In Combinators", () => {
      expect(() =>
        buildAndPolicy<TestSubject, TestResource, TestAction, TestContext>({
          policies: [],
        })
      ).toThrow("AndPolicy must have at least one policy");

      expect(() =>
        buildOrPolicy<TestSubject, TestResource, TestAction, TestContext>({
          policies: [],
        })
      ).toThrow("OrPolicy must have at least one policy");
    });

    test("Deeply Nested Combinators", async () => {
      /*
        This is a more complex example that tests the nesting and evaluation order of the policies.
            NOT(AND(Allow, OR(Deny, NOT(Deny))))
        */
      const innerDeny = buildAlwaysDenyPolicy("InnerDeny");
      const innerNot = buildNotPolicy({ policy: innerDeny });
      const midDeny = buildAlwaysDenyPolicy("MidDeny");

      const innerOr = buildOrPolicy({
        policies: [midDeny, innerNot],
      });

      const innerAnd = buildAndPolicy({
        policies: [alwaysAllowPolicy, innerOr],
      });

      const outerNot = buildNotPolicy({ policy: innerAnd });

      const result = await Effect.runPromise(
        outerNot.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );

      expect(result.isGranted()).toBe(false);

      // Verify the correct structure of the trace
      const traceStr = result.format();
      expect(traceStr).toContain("NotPolicy"); // Outer NOT
      expect(traceStr).toContain("AndPolicy"); // Inner AND
      expect(traceStr).toContain("OrPolicy"); // Inner OR
      expect(traceStr).toContain("NotPolicy"); // Inner NOT
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
      evaluateAccess: ({ context }) => {
        if (context.featureEnabled) {
          return Effect.succeed({
            policyType: "FeatureFlagPolicy",
            reason: "Feature flag enabled",
            isGranted: () => true,
            format: () =>
              "\u2714 FeatureFlagPolicy GRANTED Feature flag enabled",
          });
        } else {
          return Effect.succeed({
            policyType: "FeatureFlagPolicy",
            reason: "Feature flag disabled",
            isGranted: () => false,
            format: () =>
              "\u2718 FeatureFlagPolicy DENIED: Feature flag disabled",
          });
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
      expect(result.isGranted()).toBe(true);

      const contextDisabled: FeatureFlagContext = { featureEnabled: false };
      result = await Effect.runPromise(
        featureFlagPolicy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: contextDisabled,
        })
      );
      expect(result.isGranted()).toBe(false);
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
              return {
                policyType: name,
                reason: "Counting policy granted",
                isGranted: () => true,
                format: () => `\u2714 ${name} GRANTED Counting policy granted`,
              };
            } else {
              return {
                policyType: name,
                reason: "Counting policy denied",
                isGranted: () => false,
                format: () => `\u2718 ${name} DENIED: Counting policy denied`,
              };
            }
          }),
      };
    }

    beforeEach(() => {
      evaluationCount = 0; // Reset counter before each short-circuit test
    });

    test("AND policy should short-circuit after first deny", async () => {
      const andPolicy = buildAndPolicy({
        policies: [
          buildCountingPolicy(false), // Denies, should cause short-circuit
          buildCountingPolicy(true), // Allows, should not be evaluated
        ],
      });
      await Effect.runPromise(
        andPolicy.evaluateAccess({
          subject,
          resource,
          action: testAction,
          context: testContext,
        })
      );
      expect(evaluationCount).toBe(1);
    });

    test("OR policy should short-circuit after first allow", async () => {
      const orPolicy = buildOrPolicy({
        policies: [
          buildCountingPolicy(true), // Allows, should cause short-circuit
          buildCountingPolicy(false), // Denies, should not be evaluated
        ],
      });
      await Effect.runPromise(
        orPolicy.evaluateAccess({
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

// --- Policy Builder Tests ---
describe("PolicyBuilder", () => {
  type BuilderSubject = { name: string };
  const builderSubjectAlice: BuilderSubject = { name: "Alice" };
  const builderSubjectBob: BuilderSubject = { name: "Bob" };
  const builderSubjectAny: BuilderSubject = { name: "Any" };

  // Other types were empty structs, reuse TestAction/Resource/Context
  type BuilderResource = TestResource;
  type BuilderAction = TestAction;
  type BuilderContext = TestContext;

  test("Policy Builder Allows When No Predicates", async () => {
    const policy = new PolicyBuilder<
      BuilderSubject,
      BuilderResource,
      BuilderAction,
      BuilderContext
    >("NoPredicatesPolicy").build();

    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: builderSubjectAny,
        action: testAction,
        resource: { id: newId() },
        context: testContext,
      })
    );
    expect(result.isGranted()).toBe(true);
  });

  test("Policy Builder With Subject Predicate", async () => {
    const policy = new PolicyBuilder<
      BuilderSubject,
      BuilderResource,
      BuilderAction,
      BuilderContext
    >("SubjectPolicy")
      .subjects((s: BuilderSubject) => Effect.succeed(s.name === "Alice"))
      .build();

    // Should allow if the subject's name is "Alice"
    let result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: builderSubjectAlice,
        action: testAction,
        resource: { id: newId() },
        context: testContext,
      })
    );
    expect(result.isGranted()).toBe(true);

    // Otherwise, it should deny
    result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: builderSubjectBob,
        action: testAction,
        resource: { id: newId() },
        context: testContext,
      })
    );
    expect(result.isGranted()).toBe(false);
  });

  test("Policy Builder Effect Deny", async () => {
    const policy = new PolicyBuilder<
      BuilderSubject,
      BuilderResource,
      BuilderAction,
      BuilderContext
    >("DenyPolicy")
      .effect(PolicyEffect.Deny)
      .build();

    // Even though no predicate fails (so predicate returns true),
    // the effect should result in a Denied outcome.
    const result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: builderSubjectAny,
        action: testAction,
        resource: { id: newId() },
        context: testContext,
      })
    );
    expect(result.isGranted()).toBe(false);
  });

  test("Policy Builder With Extra Condition", async () => {
    type ExtendedSubject = {
      id: string;
      name: string;
    };
    type ExtendedResource = {
      ownerId: string;
    };
    type ExtendedAction = TestAction;
    type ExtendedContext = TestContext;

    const subjectId = newId();
    const aliceOwnerSubject: ExtendedSubject = {
      id: subjectId,
      name: "Alice",
    };
    const resourceOwnedByAlice: ExtendedResource = { ownerId: subjectId };
    const resourceOwnedByOther: ExtendedResource = { ownerId: newId() };

    // Build a policy that checks:
    //   1. Subject's name is "Alice"
    //   2. And that subject.id == resource.owner_id (via extra condition)
    const policy = new PolicyBuilder<
      ExtendedSubject,
      ExtendedResource,
      ExtendedAction,
      ExtendedContext
    >("AliceOwnerPolicy")
      .subjects((s: ExtendedSubject) => Effect.succeed(s.name === "Alice"))
      .when(({ subject, resource }) =>
        Effect.succeed(subject.id === resource.ownerId)
      )
      .build();

    // Case where both conditions are met.
    let result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: aliceOwnerSubject,
        action: testAction,
        resource: resourceOwnedByAlice,
        context: testContext,
      })
    );
    expect(result.isGranted()).toBe(true);

    // Case where extra condition fails (different id)
    result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: aliceOwnerSubject, // Still Alice
        action: testAction,
        resource: resourceOwnedByOther, // Owned by someone else
        context: testContext,
      })
    );
    expect(result.isGranted()).toBe(false);

    // Case where subject condition fails (not Alice)
    result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: { id: subjectId, name: "Bob" }, // Not Alice
        action: testAction,
        resource: resourceOwnedByAlice, // Owned by Alice's ID, but subject is Bob
        context: testContext,
      })
    );
    expect(result.isGranted()).toBe(false);
  });
});
