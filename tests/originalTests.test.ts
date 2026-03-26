import { describe, test, expect, beforeEach } from "bun:test";
import { Effect } from "effect";
import {
  buildAndPolicy,
  buildNotPolicy,
  buildOrPolicy,
  buildRebacPolicy,
  checkPermissions,
  DeniedAccessResult,
  formatResult,
  getDisplayTrace,
  GrantedAccessResult,
  isGranted,
  makePolicy,
  type Policy,
  type PolicyEvalResult,
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
    const result = await Effect.runPromise(
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
    const result = await Effect.runPromise(
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
    const result = await Effect.runPromise(
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

    const result = await Effect.runPromise(
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

    const result = await Effect.runPromise(
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
      expect(isGranted(result)).toBe(true);
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
      expect(isGranted(result)).toBe(false);
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
      expect(isGranted(result)).toBe(true);
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
      expect(isGranted(result)).toBe(false);
      const traceStr = formatResult(result);
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
      expect(isGranted(result)).toBe(true);
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
      expect(isGranted(result)).toBe(false);
      const traceStr = formatResult(result);
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
      expect(isGranted(result)).toBe(true);
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
      expect(isGranted(result)).toBe(false);
      const traceStr = formatResult(result);
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

      expect(isGranted(result)).toBe(false);

      // Verify the correct structure of the trace
      const traceStr = formatResult(result);
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

// --- makePolicy Tests ---
describe("makePolicy", () => {
  type BuilderSubject = { name: string };
  const builderSubjectAlice: BuilderSubject = { name: "Alice" };
  const builderSubjectBob: BuilderSubject = { name: "Bob" };
  const builderSubjectAny: BuilderSubject = { name: "Any" };

  // Other types were empty structs, reuse TestAction/Resource/Context
  type BuilderResource = TestResource;
  type BuilderAction = TestAction;
  type BuilderContext = TestContext;

  test("Policy Allows When No Predicates", async () => {
    const policy = makePolicy<
      BuilderSubject,
      BuilderResource,
      BuilderAction,
      BuilderContext
    >("NoPredicatesPolicy");

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
    const policy = makePolicy<
      BuilderSubject,
      BuilderResource,
      BuilderAction,
      BuilderContext
    >("SubjectPolicy", {
      subject: (s) => Effect.succeed(s.name === "Alice"),
    });

    // Should allow if the subject's name is "Alice"
    let result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: builderSubjectAlice,
        action: testAction,
        resource: { id: newId() },
        context: testContext,
      })
    );
    expect(isGranted(result)).toBe(true);

    // Otherwise, it should deny
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

  test("Policy Effect Deny", async () => {
    const policy = makePolicy<
      BuilderSubject,
      BuilderResource,
      BuilderAction,
      BuilderContext
    >("DenyPolicy", {
      intent: 'deny',
    });

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
    expect(isGranted(result)).toBe(false);
  });

  test("Policy With Extra Condition", async () => {
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
    const policy = makePolicy<
      ExtendedSubject,
      ExtendedResource,
      ExtendedAction,
      ExtendedContext
    >("AliceOwnerPolicy", {
      subject: (s) => Effect.succeed(s.name === "Alice"),
      when: ({ subject, resource }) =>
        Effect.succeed(subject.id === resource.ownerId),
    });

    // Case where both conditions are met.
    let result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: aliceOwnerSubject,
        action: testAction,
        resource: resourceOwnedByAlice,
        context: testContext,
      })
    );
    expect(isGranted(result)).toBe(true);

    // Case where extra condition fails (different id)
    result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: aliceOwnerSubject, // Still Alice
        action: testAction,
        resource: resourceOwnedByOther, // Owned by someone else
        context: testContext,
      })
    );
    expect(isGranted(result)).toBe(false);

    // Case where subject condition fails (not Alice)
    result = await Effect.runPromise(
      policy.evaluateAccess({
        subject: { id: subjectId, name: "Bob" }, // Not Alice
        action: testAction,
        resource: resourceOwnedByAlice, // Owned by Alice's ID, but subject is Bob
        context: testContext,
      })
    );
    expect(isGranted(result)).toBe(false);
  });
});
