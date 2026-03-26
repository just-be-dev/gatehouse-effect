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
 * Use `Effect.catch` to unify both channels for inspection:
 * ```ts
 * const check = checkPermissions([rbacPolicy, abacPolicy])
 * const result = yield* check({ subject, resource, action, context }).pipe(
 *   Effect.catch((e) => Effect.succeed(e))
 * )
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

const wrap = (name: string): string =>
  name.includes(' & ') || name.includes(' | ') ? `(${name})` : name;

// ---- AND Policy ----

/**
 * Creates a policy that requires all sub-policies to grant access.
 *
 * @example
 * ```ts
 * buildAndPolicy([ownerPolicy, privatePolicy])
 * buildAndPolicy("OwnerAndPrivate", [ownerPolicy, privatePolicy])
 * ```
 */
function buildAndPolicy<Sub, Res, Act, Ctx>(
  nameOrPolicies: string | Policy<Sub, Res, Act, Ctx>[],
  maybePolicies?: Policy<Sub, Res, Act, Ctx>[]
): Policy<Sub, Res, Act, Ctx> {
  const policies = typeof nameOrPolicies === 'string' ? maybePolicies! : nameOrPolicies;

  if (!policies.length) {
    throw new Error('AndPolicy must have at least one policy');
  }

  const name = typeof nameOrPolicies === 'string'
    ? nameOrPolicies
    : policies.map((p) => wrap(p.name)).join(' & ');

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
 *
 * @example
 * ```ts
 * buildOrPolicy([ownerPolicy, adminPolicy])
 * buildOrPolicy("OwnerOrAdmin", [ownerPolicy, adminPolicy])
 * ```
 */
function buildOrPolicy<Sub, Res, Act, Ctx>(
  nameOrPolicies: string | Policy<Sub, Res, Act, Ctx>[],
  maybePolicies?: Policy<Sub, Res, Act, Ctx>[]
): Policy<Sub, Res, Act, Ctx> {
  const policies = typeof nameOrPolicies === 'string' ? maybePolicies! : nameOrPolicies;

  if (!policies.length) {
    throw new Error('OrPolicy must have at least one policy');
  }

  const name = typeof nameOrPolicies === 'string'
    ? nameOrPolicies
    : policies.map((p) => wrap(p.name)).join(' | ');

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
 *
 * @example
 * ```ts
 * invertPolicy(publicPolicy)
 * invertPolicy("NotPublic", publicPolicy)
 * ```
 */
function invertPolicy<Sub, Res, Act, Ctx>(
  nameOrPolicy: string | Policy<Sub, Res, Act, Ctx>,
  maybePolicy?: Policy<Sub, Res, Act, Ctx>
): Policy<Sub, Res, Act, Ctx> {
  const name = typeof nameOrPolicy === 'string' ? nameOrPolicy : `!${wrap(nameOrPolicy.name)}`;
  const policy = typeof nameOrPolicy === 'string' ? maybePolicy! : nameOrPolicy;

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

// ---- combinePolicy ----

interface Combinators<Sub, Res, Act, Ctx> {
  and: (...policies: Policy<Sub, Res, Act, Ctx>[]) => Policy<Sub, Res, Act, Ctx>;
  or: (...policies: Policy<Sub, Res, Act, Ctx>[]) => Policy<Sub, Res, Act, Ctx>;
  not: (policy: Policy<Sub, Res, Act, Ctx>) => Policy<Sub, Res, Act, Ctx>;
}

type CombineFn<Sub, Res, Act, Ctx> = (combinators: Combinators<Sub, Res, Act, Ctx>) => Policy<Sub, Res, Act, Ctx>;

/**
 * Compose policies using `and`, `or`, and `not` combinators in a single expression.
 *
 * @example
 * ```ts
 * combinePolicy((and, or, not) => and(rbacPolicy, or(abacPolicy, not(publicPolicy))))
 * combinePolicy("CustomName", (and, or, not) => and(policy1, not(policy2)))
 * ```
 */
function combinePolicy<Sub, Res, Act, Ctx>(
  nameOrFn: string | CombineFn<Sub, Res, Act, Ctx>,
  maybeFn?: CombineFn<Sub, Res, Act, Ctx>,
): Policy<Sub, Res, Act, Ctx> {
  const name = typeof nameOrFn === 'string' ? nameOrFn : undefined;
  const fn = typeof nameOrFn === 'string' ? maybeFn! : nameOrFn;

  const combinators: Combinators<Sub, Res, Act, Ctx> = {
    and: (...policies) => buildAndPolicy<Sub, Res, Act, Ctx>(policies),
    or: (...policies) => buildOrPolicy<Sub, Res, Act, Ctx>(policies),
    not: (policy) => invertPolicy<Sub, Res, Act, Ctx>(policy),
  };

  const result = fn(combinators);

  if (name) {
    return { name, evaluateAccess: result.evaluateAccess };
  }
  return result;
}

// ---- Policy Factory ----

/**
 * Creates a typed policy factory from schemas. Types are inferred from the
 * schemas so no generic parameters are needed on individual policy definitions.
 *
 * Actions can be specified as literals (`"read"`), arrays (`["read", "write"]`),
 * or predicate functions.
 *
 * @example
 * ```ts
 * const define = policyFactory({
 *   subject: UserSchema,
 *   resource: DocumentSchema,
 *   action: Schema.Literal("read", "write", "delete"),
 *   context: ContextSchema,
 * });
 *
 * const readOnly = define("ReadOnly", { action: "read" });
 * const rbac = define.rbac("RBAC", { roles: { read: ["viewer"], write: ["editor"] }, userRoles: (s) => s.roles });
 * ```
 */
function policyFactory<
  SubjectSchema extends Schema.Top,
  ResourceSchema extends Schema.Top,
  ActionSchema extends Schema.Top,
  ContextSchema extends Schema.Top,
>(_schemas: {
  subject: SubjectSchema;
  resource: ResourceSchema;
  action: ActionSchema;
  context: ContextSchema;
}) {
  type Sub = Schema.Schema.Type<SubjectSchema>;
  type Res = Schema.Schema.Type<ResourceSchema>;
  type Act = Schema.Schema.Type<ActionSchema>;
  type Ctx = Schema.Schema.Type<ContextSchema>;

  function define(
    name: string,
    options: {
      intent?: PolicyIntent;
      subject?: (sub: Sub) => Effectful<boolean>;
      resource?: (res: Res) => Effectful<boolean>;
      action?: Act | ReadonlyArray<Act> | ((act: Act) => Effectful<boolean>);
      context?: (ctx: Ctx) => Effectful<boolean>;
      when?: (args: { subject: Sub; resource: Res; action: Act; context: Ctx }) => Effectful<boolean>;
    } = {}
  ): Policy<Sub, Res, Act, Ctx> {
    let actionPred: ((act: Act) => Effectful<boolean>) | undefined;

    if (options.action !== undefined) {
      if (typeof options.action === 'function') {
        actionPred = options.action as (act: Act) => Effectful<boolean>;
      } else if (Array.isArray(options.action)) {
        const allowed = options.action as ReadonlyArray<Act>;
        actionPred = (a: Act) => allowed.includes(a);
      } else {
        const expected = options.action as Act;
        actionPred = (a: Act) => a === expected;
      }
    }

    const policyOptions: Parameters<typeof makePolicy<Sub, Res, Act, Ctx>>[1] = {};
    if (options.intent !== undefined) policyOptions.intent = options.intent;
    if (options.subject !== undefined) policyOptions.subject = options.subject;
    if (options.resource !== undefined) policyOptions.resource = options.resource;
    if (actionPred !== undefined) policyOptions.action = actionPred;
    if (options.context !== undefined) policyOptions.context = options.context;
    if (options.when !== undefined) policyOptions.when = options.when;

    return makePolicy<Sub, Res, Act, Ctx>(name, policyOptions);
  }

  function rbac<Role>(
    name: string,
    options: {
      roles: { [K in Act & string]: ReadonlyArray<Role> };
      userRoles: (sub: Sub) => Effectful<Role[]>;
    }
  ): Policy<Sub, Res, Act, Ctx> {
    const roleMap = options.roles as Record<string, ReadonlyArray<Role>>;
    return buildRbacPolicy<Sub, Res, Act, Ctx, Role>({
      name,
      requiredRolesResolver: (_res: Res, act: Act) => (roleMap[act as string] ?? []) as Role[],
      userRolesResolver: options.userRoles,
    });
  }

  function rebac(
    name: string,
    options: {
      relationship: string;
      resolver: (args: { subject: Sub; resource: Res }) => Effectful<boolean>;
    }
  ): Policy<Sub, Res, Act, Ctx> {
    return buildRebacPolicy<Sub, Res, Act, Ctx>({
      name,
      relationship: options.relationship,
      resolver: ({ subject, resource }) => options.resolver({ subject, resource }),
    });
  }

  function combine(
    nameOrFn: string | CombineFn<Sub, Res, Act, Ctx>,
    maybeFn?: CombineFn<Sub, Res, Act, Ctx>,
  ): Policy<Sub, Res, Act, Ctx> {
    return combinePolicy<Sub, Res, Act, Ctx>(nameOrFn, maybeFn);
  }

  return Object.assign(define, { rbac, rebac, combine });
}

export {
  AccessDenied,
  AccessGranted,
  checkPermissions,
  type CombineOp,
  combinePolicy,
  CombinedResult,
  DeniedAccessResult,
  formatResult,
  getDisplayTrace,
  GrantedAccessResult,
  invertPolicy,
  isGranted,
  NoPoliciesError,
  type Policy,
  policyFactory,
  type PolicyEvalResult,
};
