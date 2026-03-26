import { Data, Effect, Match, Schema } from 'effect';

type CombineOp = 'and' | 'or' | 'not';

/**
 * Whether a policy grants or denies access when its predicates match.
 */
type PolicyIntent = 'allow' | 'deny';

// ---- Result Types ----

/**
 * Discriminated union of all policy evaluation results.
 * Use `isGranted` or `Match.valueTags` to inspect.
 */
type PolicyEvalResult = GrantedAccessResult | DeniedAccessResult | CombinedResult;

/**
 * Represents a successful policy evaluation that grants access.
 */
class GrantedAccessResult extends Schema.TaggedClass<GrantedAccessResult>()('GrantedAccessResult', {
  policyType: Schema.String,
  reason: Schema.NullOr(Schema.String),
}) {}

/**
 * Represents a failed policy evaluation that denies access.
 */
class DeniedAccessResult extends Schema.TaggedClass<DeniedAccessResult>()('DeniedAccessResult', {
  policyType: Schema.String,
  reason: Schema.NullOr(Schema.String),
}) {}

/**
 * Represents a combined result from multiple policies.
 * Kept as Data.TaggedClass due to recursive PolicyEvalResult references.
 */
class CombinedResult
  extends Data.TaggedClass('CombinedResult')<{
    readonly policyType: string;
    readonly outcome: boolean;
    readonly operation: CombineOp;
    readonly children: ReadonlyArray<PolicyEvalResult>;
  }>
{}

/**
 * Check if a policy evaluation result grants access.
 */
function isGranted(result: PolicyEvalResult): boolean {
  return Match.valueTags(result, {
    GrantedAccessResult: () => true,
    DeniedAccessResult: () => false,
    CombinedResult: (r) => r.outcome,
  });
}

/**
 * Format a policy evaluation result as a human-readable string.
 */
function formatResult(result: PolicyEvalResult): string {
  return Match.valueTags(result, {
    GrantedAccessResult: (r) => `\u2714 ${r.policyType} GRANTED${r.reason ? ' ' + r.reason : ''}`,
    DeniedAccessResult: (r) => `\u2718 ${r.policyType} DENIED: ${r.reason ? ' ' + r.reason : ''}`,
    CombinedResult: (r) => {
      const outcomeChar = r.outcome ? '\u2714' : '\u2718';
      const toplevelMessage = `${outcomeChar} ${r.policyType} (${r.operation})`;
      return [toplevelMessage, ...r.children.map((child) => '  ' + formatResult(child))].join(
        '\n'
      );
    },
  });
}

// ---- Access Evaluation Results ----

/**
 * Represents a granted access evaluation result.
 */
class AccessGranted extends Schema.TaggedClass<AccessGranted>()('AccessGranted', {
  policyType: Schema.String,
  reason: Schema.NullOr(Schema.String),
  trace: Schema.NullOr(Schema.Any),
}) {}

/**
 * Represents a denied access evaluation (typed error in the Effect error channel).
 */
class AccessDenied extends Schema.TaggedErrorClass<AccessDenied>()('AccessDenied', {
  reason: Schema.String,
  trace: Schema.NullOr(Schema.Any),
}) {}

/**
 * Error for when no policies are configured.
 */
class NoPoliciesError extends Schema.TaggedErrorClass<NoPoliciesError>()('NoPoliciesError', {
  message: Schema.String,
  trace: Schema.NullOr(Schema.Any),
}) {}

/**
 * Get a formatted display trace from an access result or error.
 */
function getDisplayTrace(result: AccessGranted | AccessDenied | NoPoliciesError): string {
  const trace = result.trace as PolicyEvalResult | null;
  if (trace) {
    return `\nEvaluation Trace:\n${formatResult(trace)}`;
  }
  return '\n(No evaluation trace available)';
}

// ---- Policy Types ----

/**
 * A policy evaluates access for a given subject, resource, action, and context.
 */
interface Policy<Subject, Resource, Action, Context> {
  readonly name: string;
  readonly evaluateAccess: (args: {
    subject: Subject;
    resource: Resource;
    action: Action;
    context: Context;
  }) => Effect.Effect<PolicyEvalResult>;
}

/**
 * A value that is either a plain boolean or an Effect that produces a boolean.
 */
type Effectful<T> = T | Effect.Effect<T>;

/**
 * A condition checks if access should be granted.
 */
type Condition<Subject, Resource, Action, Context> = (args: {
  subject: Subject;
  resource: Resource;
  action: Action;
  context: Context;
}) => Effectful<boolean>;

/**
 * Resolves whether a relationship exists between a subject and resource.
 */
type RelationshipResolver<Subject, Resource> = (args: {
  subject: Subject;
  resource: Resource;
  relationship: string;
}) => Effectful<boolean>;

const resolve = <T>(value: Effectful<T>): Effect.Effect<T> =>
  Effect.isEffect(value) ? value : Effect.succeed(value as T);

// ---- makePolicy ----

/**
 * Creates a custom policy from individual predicate functions.
 * All predicates are AND'd together. Omitted predicates default to true.
 */
function makePolicy<Sub, Res, Act, Ctx>(
  name: string,
  options: {
    intent?: PolicyIntent;
    subject?: (sub: Sub) => Effectful<boolean>;
    resource?: (res: Res) => Effectful<boolean>;
    action?: (act: Act) => Effectful<boolean>;
    context?: (ctx: Ctx) => Effectful<boolean>;
    when?: Condition<Sub, Res, Act, Ctx>;
  } = {}
): Policy<Sub, Res, Act, Ctx> {
  const intent = options.intent ?? 'allow';
  const { subject: subjectPred, resource: resPred, action: actionPred, context: ctxPred, when: extraPred } = options;

  const evaluateAccess = Effect.fn(`${name}.evaluateAccess`)(function* (args: {
    subject: Sub;
    resource: Res;
    action: Act;
    context: Ctx;
  }) {
    const predicateResult =
      (subjectPred === undefined || (yield* resolve(subjectPred(args.subject)))) &&
      (resPred === undefined || (yield* resolve(resPred(args.resource)))) &&
      (actionPred === undefined || (yield* resolve(actionPred(args.action)))) &&
      (ctxPred === undefined || (yield* resolve(ctxPred(args.context)))) &&
      (extraPred === undefined || (yield* resolve(extraPred(args))));

    if (predicateResult) {
      if (intent === 'allow') {
        return new GrantedAccessResult({ policyType: name, reason: 'Policy allowed access' });
      }
      return new DeniedAccessResult({ policyType: name, reason: 'Policy denied access' });
    }
    return new DeniedAccessResult({ policyType: name, reason: 'Policy predicate did not match' });
  });

  return { name, evaluateAccess };
}

// ---- checkPermissions ----

/**
 * Evaluates policies sequentially until one grants access (first-grant-wins).
 * Returns a curried function: provide policies, then call with access args.
 *
 * Succeeds with `AccessGranted` or fails with `AccessDenied | NoPoliciesError`.
 *
 * Use `Effect.merge` to unify both channels for inspection:
 * ```ts
 * const check = checkPermissions([rbacPolicy, abacPolicy])
 * const result = yield* check({ subject, resource, action, context }).pipe(Effect.merge)
 * ```
 */
function checkPermissions<Sub, Res, Act, Ctx>(
  policies: ReadonlyArray<Policy<Sub, Res, Act, Ctx>>
): (args: {
  subject: Sub;
  resource: Res;
  action: Act;
  context: Ctx;
}) => Effect.Effect<AccessGranted, AccessDenied | NoPoliciesError> {
  return ({ subject, resource, action, context }) => {
    if (!policies.length) {
      const reason = 'No policies configured';
      return Effect.fail(
        new NoPoliciesError({
          message: reason,
          trace: new DeniedAccessResult({ policyType: 'checkPermissions', reason }),
        })
      );
    }

    return Effect.gen(function* () {
      const policyResults: PolicyEvalResult[] = [];

      for (const policy of policies) {
        const result: PolicyEvalResult = yield* policy.evaluateAccess({
          subject,
          resource,
          action,
          context,
        });
        policyResults.push(result);

        if (isGranted(result)) {
          const combined = new CombinedResult({
            policyType: 'checkPermissions',
            outcome: true,
            operation: 'or',
            children: policyResults,
          });
          return new AccessGranted({
            policyType: result.policyType,
            reason: null,
            trace: combined,
          });
        }
      }

      const combined = new CombinedResult({
        policyType: 'checkPermissions',
        outcome: false,
        operation: 'or',
        children: policyResults,
      });
      return yield* new AccessDenied({
        reason: 'All policies denied access',
        trace: combined,
      });
    }).pipe(Effect.withSpan('checkPermissions'));
  };
}

// ---- RBAC ----

/**
 * Creates a Role-Based Access Control policy.
 */
function buildRbacPolicy<Sub, Res, Act, Ctx, Role>({
  requiredRolesResolver,
  userRolesResolver,
  name = 'RbacPolicy',
}: {
  requiredRolesResolver: (res: Res, act: Act) => Effectful<Role[]>;
  userRolesResolver: (sub: Sub) => Effectful<Role[]>;
  name?: string;
}): Policy<Sub, Res, Act, Ctx> {
  const evaluateAccess = Effect.fn(`${name}.evaluateAccess`)(function* ({
    subject,
    resource,
    action,
  }: {
    subject: Sub;
    resource: Res;
    action: Act;
    context: Ctx;
  }) {
    const requiredRoles: Role[] = yield* resolve(requiredRolesResolver(resource, action));
    const userRoles: Role[] = yield* resolve(userRolesResolver(subject));
    const hasRole: boolean = requiredRoles.some((role) => userRoles.includes(role));
    if (hasRole) {
      return new GrantedAccessResult({ policyType: name, reason: 'User has required role' });
    }
    return new DeniedAccessResult({ policyType: name, reason: "User doesn't have required role" });
  });

  return { name, evaluateAccess };
}

// ---- ABAC ----

/**
 * Creates an Attribute-Based Access Control policy.
 */
function buildAbacPolicy<Sub, Res, Act, Ctx>({
  condition,
  name = 'AbacPolicy',
}: {
  condition: Condition<Sub, Res, Act, Ctx>;
  name?: string;
}): Policy<Sub, Res, Act, Ctx> {
  return makePolicy(name, { when: condition });
}

// ---- ReBAC ----

/**
 * Creates a Relationship-Based Access Control policy.
 */
function buildRebacPolicy<Sub, Res, Act, Ctx>({
  relationship,
  resolver,
  name = 'RebacPolicy',
}: {
  relationship: string;
  resolver: RelationshipResolver<Sub, Res>;
  name?: string;
}): Policy<Sub, Res, Act, Ctx> {
  const evaluateAccess = Effect.fn(`${name}.evaluateAccess`)(function* ({
    subject,
    resource,
  }: {
    subject: Sub;
    resource: Res;
    action: Act;
    context: Ctx;
  }) {
    const hasRelationship: boolean = yield* resolve(resolver({ subject, resource, relationship }));
    if (hasRelationship) {
      return new GrantedAccessResult({
        policyType: name,
        reason: `Subject has ${relationship} relationship with resource`,
      });
    }
    return new DeniedAccessResult({
      policyType: name,
      reason: `Subject does not have ${relationship} relationship with resource`,
    });
  });

  return { name, evaluateAccess };
}

// ---- AND Policy ----

/**
 * Creates a policy that requires all sub-policies to grant access.
 */
function buildAndPolicy<Sub, Res, Act, Ctx>({
  policies,
  name = 'AndPolicy',
}: {
  policies: Policy<Sub, Res, Act, Ctx>[];
  name?: string;
}): Policy<Sub, Res, Act, Ctx> {
  if (!policies.length) {
    throw new Error('AndPolicy must have at least one policy');
  }

  const evaluateAccess = Effect.fn(`${name}.evaluateAccess`)(function* (args: {
    subject: Sub;
    resource: Res;
    action: Act;
    context: Ctx;
  }) {
    const results: PolicyEvalResult[] = [];
    for (const policy of policies) {
      const result = yield* policy.evaluateAccess(args);
      results.push(result);

      if (!isGranted(result)) {
        return new CombinedResult({
          policyType: name,
          outcome: false,
          operation: 'and',
          children: results,
        });
      }
    }
    return new CombinedResult({
      policyType: name,
      outcome: true,
      operation: 'and',
      children: results,
    });
  });

  return { name, evaluateAccess };
}

// ---- OR Policy ----

/**
 * Creates a policy that grants access if any sub-policy grants access.
 */
function buildOrPolicy<Sub, Res, Act, Ctx>({
  policies,
  name = 'OrPolicy',
}: {
  policies: Policy<Sub, Res, Act, Ctx>[];
  name?: string;
}): Policy<Sub, Res, Act, Ctx> {
  if (!policies.length) {
    throw new Error('OrPolicy must have at least one policy');
  }

  const evaluateAccess = Effect.fn(`${name}.evaluateAccess`)(function* (args: {
    subject: Sub;
    resource: Res;
    action: Act;
    context: Ctx;
  }) {
    const results: PolicyEvalResult[] = [];
    for (const policy of policies) {
      const result = yield* policy.evaluateAccess(args);
      results.push(result);

      if (isGranted(result)) {
        return new CombinedResult({
          policyType: name,
          outcome: true,
          operation: 'or',
          children: results,
        });
      }
    }
    return new CombinedResult({
      policyType: name,
      outcome: false,
      operation: 'or',
      children: results,
    });
  });

  return { name, evaluateAccess };
}

// ---- NOT Policy ----

/**
 * Creates a policy that inverts the result of another policy.
 */
function buildNotPolicy<Sub, Res, Act, Ctx>({
  policy,
  name = 'NotPolicy',
}: {
  policy: Policy<Sub, Res, Act, Ctx>;
  name?: string;
}): Policy<Sub, Res, Act, Ctx> {
  const evaluateAccess = Effect.fn(`${name}.evaluateAccess`)(function* (args: {
    subject: Sub;
    resource: Res;
    action: Act;
    context: Ctx;
  }) {
    const result = yield* policy.evaluateAccess(args);
    return new CombinedResult({
      policyType: name,
      outcome: !isGranted(result),
      operation: 'not',
      children: [result],
    });
  });

  return { name, evaluateAccess };
}

export {
  AccessDenied,
  AccessGranted,
  buildAbacPolicy,
  buildAndPolicy,
  buildNotPolicy,
  buildOrPolicy,
  buildRbacPolicy,
  buildRebacPolicy,
  checkPermissions,
  type CombineOp,
  CombinedResult,
  type Condition,
  DeniedAccessResult,
  type Effectful,
  formatResult,
  getDisplayTrace,
  GrantedAccessResult,
  isGranted,
  makePolicy,
  NoPoliciesError,
  type Policy,
  type PolicyIntent,
  type PolicyEvalResult,
  type RelationshipResolver,
};
