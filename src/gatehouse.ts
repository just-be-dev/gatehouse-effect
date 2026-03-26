import { Data, Effect } from 'effect';

/**
 * Operation types for combining policies.
 */
const CombineOp = {
  And: 'AND',
  Or: 'OR',
  Not: 'NOT',
} as const;

type Operation = (typeof CombineOp)[keyof typeof CombineOp];

/**
 * Represents the intended effect of a policy.
 * `Allow` means the policy grants access; `Deny` means it denies access.
 *
 * Renamed from `Effect` to avoid conflict with the Effect library.
 */
const PolicyEffect = {
  Allow: 'Allow',
  Deny: 'Deny',
} as const;

type IntendedEffect = (typeof PolicyEffect)[keyof typeof PolicyEffect];

// ---- Result Types ----

/**
 * Common interface for all policy evaluation results.
 */
interface PolicyEvalResult {
  readonly policyType: string;
  readonly reason: string | null;
  isGranted(): boolean;
  format(): string;
}

/**
 * Represents a successful policy evaluation that grants access.
 */
class GrantedAccessResult
  extends Data.TaggedClass('GrantedAccessResult')<{
    readonly policyType: string;
    readonly reason: string | null;
  }>
  implements PolicyEvalResult
{
  isGranted(): boolean {
    return true;
  }
  format(): string {
    return `\u2714 ${this.policyType} GRANTED${this.reason ? ' ' + this.reason : ''}`;
  }
}

/**
 * Represents a failed policy evaluation that denies access.
 */
class DeniedAccessResult
  extends Data.TaggedClass('DeniedAccessResult')<{
    readonly policyType: string;
    readonly reason: string | null;
  }>
  implements PolicyEvalResult
{
  isGranted(): boolean {
    return false;
  }
  format(): string {
    return `\u2718 ${this.policyType} DENIED: ${this.reason ? ' ' + this.reason : ''}`;
  }
}

/**
 * Represents a combined result from multiple policies.
 * Used for AND, OR, and NOT policy combinations.
 */
class CombinedResult
  extends Data.TaggedClass('CombinedResult')<{
    readonly policyType: string;
    readonly reason: string | null;
    readonly outcome: boolean;
    readonly operation: Operation;
    readonly children: ReadonlyArray<PolicyEvalResult>;
  }>
  implements PolicyEvalResult
{
  isGranted(): boolean {
    return this.outcome;
  }
  format(): string {
    const outcomeChar: string = this.outcome ? '\u2714' : '\u2718';
    const toplevelMessage = `${outcomeChar} ${this.policyType} (${this.operation})`;
    return [toplevelMessage, ...this.children.map((child) => '  ' + child.format())].join('\n');
  }
  display() {
    console.log(this.format());
  }
}

/**
 * Contains the full evaluation trace for debugging policy decisions.
 */
class EvalTrace
  extends Data.TaggedClass('EvalTrace')<{
    readonly root: PolicyEvalResult | null;
  }>
{
  format(): string {
    return this.root?.format() || 'No evaluation trace available';
  }
}

// ---- Access Evaluation Results ----

/**
 * Represents a granted access evaluation result.
 */
class AccessGranted
  extends Data.TaggedClass('AccessGranted')<{
    readonly policyType: string;
    readonly reason: string | null;
    readonly trace: EvalTrace;
  }>
{
  isGranted(): true {
    return true;
  }

  getDisplayTrace(): string {
    const traceString = this.trace.format();
    return traceString !== 'No evaluation trace available'
      ? `\nEvaluation Trace:\n${traceString}`
      : `\n(${traceString})`;
  }

  print() {
    console.log(
      `[GRANTED] by ${this.policyType}${this.reason ? ` - ${this.reason}` : ''}`
    );
  }
}

/**
 * Represents a denied access evaluation (typed error in the Effect error channel).
 */
class AccessDenied
  extends Data.TaggedError('AccessDenied')<{
    readonly reason: string;
    readonly trace: EvalTrace;
  }>
{
  isGranted(): false {
    return false;
  }

  getDisplayTrace(): string {
    const traceString = this.trace.format();
    return traceString !== 'No evaluation trace available'
      ? `\nEvaluation Trace:\n${traceString}`
      : `\n(${traceString})`;
  }

  print() {
    console.log(`[DENIED] - ${this.reason}`);
  }
}

/**
 * Error for when no policies are configured in a PermissionChecker.
 */
class NoPoliciesError
  extends Data.TaggedError('NoPoliciesError')<{
    readonly message: string;
    readonly trace: EvalTrace;
  }>
{
  isGranted(): false {
    return false;
  }

  getDisplayTrace(): string {
    const traceString = this.trace.format();
    return traceString !== 'No evaluation trace available'
      ? `\nEvaluation Trace:\n${traceString}`
      : `\n(${traceString})`;
  }

  print() {
    console.log(`[DENIED] - ${this.message}`);
  }
}

// ---- Policy Types ----

/**
 * Function type for evaluating access. Returns an Effect instead of a Promise.
 */
type EvaluateAccess<Subject, Resource, Action, Context> = (args: {
  subject: Subject;
  resource: Resource;
  action: Action;
  context: Context;
}) => Effect.Effect<PolicyEvalResult>;

/**
 * Interface for all policy types in the system.
 */
interface Policy<Subject, Resource, Action, Context> {
  readonly evaluateAccess: EvaluateAccess<Subject, Resource, Action, Context>;
  readonly name: string;
}

/**
 * Function type for checking if access conditions are met.
 * Returns an Effect<boolean> instead of boolean | Promise<boolean>.
 */
type Condition<Subject, Resource, Action, Context> = (args: {
  subject: Subject;
  resource: Resource;
  action: Action;
  context: Context;
}) => Effect.Effect<boolean>;

/**
 * Function type for resolving relationships between subjects and resources.
 */
type RelationshipResolver<Subject, Resource> = (args: {
  subject: Subject;
  resource: Resource;
  relationship: string;
}) => Effect.Effect<boolean>;

// ---- Internal Policy ----

type InternalPolicy<Sub, Res, Act, Ctx> = {
  name: string;
  effect: IntendedEffect;
  predicate: (
    subject: Sub,
    resource: Res,
    action: Act,
    context: Ctx
  ) => Effect.Effect<boolean>;
};

function transformInternalPolicy<Sub, Res, Act, Ctx>(
  internalPolicy: InternalPolicy<Sub, Res, Act, Ctx>
): Policy<Sub, Res, Act, Ctx> {
  const policyName: string = internalPolicy.name;
  const intendedEffect: IntendedEffect = internalPolicy.effect;
  return Object.freeze({
    name: policyName,
    evaluateAccess: ({
      subject,
      resource,
      action,
      context,
    }: {
      subject: Sub;
      resource: Res;
      action: Act;
      context: Ctx;
    }): Effect.Effect<PolicyEvalResult> =>
      Effect.gen(function* () {
        const predicateResult = yield* internalPolicy.predicate(
          subject,
          resource,
          action,
          context
        );
        if (predicateResult) {
          if (intendedEffect === PolicyEffect.Allow) {
            return new GrantedAccessResult({
              policyType: policyName,
              reason: 'Policy allowed access',
            });
          }
          return new DeniedAccessResult({
            policyType: policyName,
            reason: 'Policy denied access',
          });
        }
        return new DeniedAccessResult({
          policyType: policyName,
          reason: 'Policy predicate did not match',
        });
      }),
  });
}

// ---- PermissionChecker ----

/**
 * Main class for evaluating access permissions. Add multiple policies to it,
 * and it will evaluate them sequentially until one grants access.
 *
 * `evaluateAccess` returns an Effect that succeeds with `AccessGranted`
 * or fails with `AccessDenied | NoPoliciesError`.
 *
 * Use `Effect.merge` to unify both channels for inspection:
 * ```ts
 * const result = yield* checker.evaluateAccess({ ... }).pipe(Effect.merge)
 * if (result.isGranted()) { ... }
 * ```
 */
class PermissionChecker<Sub, Res, Act, Ctx> {
  private policies: Policy<Sub, Res, Act, Ctx>[] = [];
  public readonly name: string = 'PermissionChecker';

  addPolicy(policy: Policy<Sub, Res, Act, Ctx>) {
    this.policies.push(policy);
  }

  evaluateAccess({
    subject,
    resource,
    action,
    context,
  }: {
    subject: Sub;
    resource: Res;
    action: Act;
    context: Ctx;
  }): Effect.Effect<AccessGranted, AccessDenied | NoPoliciesError> {
    const policies = this.policies;

    if (!policies.length) {
      const reason: string = 'No policies configured';
      const result = new DeniedAccessResult({
        policyType: 'PermissionChecker',
        reason,
      });
      return Effect.fail(
        new NoPoliciesError({
          message: reason,
          trace: new EvalTrace({ root: result }),
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

        if (result.isGranted()) {
          const combined = new CombinedResult({
            policyType: 'PermissionChecker',
            reason: null,
            outcome: true,
            operation: CombineOp.Or,
            children: policyResults,
          });
          return new AccessGranted({
            policyType: result.policyType,
            reason: null,
            trace: new EvalTrace({ root: combined }),
          });
        }
      }

      const combined = new CombinedResult({
        policyType: 'PermissionChecker',
        reason: null,
        outcome: false,
        operation: CombineOp.Or,
        children: policyResults,
      });
      return yield* new AccessDenied({
        reason: 'All policies denied access',
        trace: new EvalTrace({ root: combined }),
      });
    });
  }
}

// ---- PolicyBuilder ----

/**
 * A fluent builder for creating custom access policies.
 * Predicates now return Effect<boolean> instead of boolean | Promise<boolean>.
 */
class PolicyBuilder<Sub, Res, Act, Ctx> {
  private _name: string;
  private _effect: IntendedEffect;

  private subjectPred: ((sub: Sub) => Effect.Effect<boolean>) | null = null;
  private resPred: ((res: Res) => Effect.Effect<boolean>) | null = null;
  private actionPred: ((act: Act) => Effect.Effect<boolean>) | null = null;
  private ctxPred: ((ctx: Ctx) => Effect.Effect<boolean>) | null = null;
  private extraConditionPred: Condition<Sub, Res, Act, Ctx> | null = null;

  constructor(name: string) {
    this._name = name;
    this._effect = PolicyEffect.Allow;
  }

  effect(effect: IntendedEffect) {
    this._effect = effect;
    return this;
  }

  subjects(pred: (sub: Sub) => Effect.Effect<boolean>) {
    this.subjectPred = pred;
    return this;
  }

  resources(pred: (res: Res) => Effect.Effect<boolean>) {
    this.resPred = pred;
    return this;
  }

  actions(pred: (action: Act) => Effect.Effect<boolean>) {
    this.actionPred = pred;
    return this;
  }

  context(pred: (ctx: Ctx) => Effect.Effect<boolean>) {
    this.ctxPred = pred;
    return this;
  }

  when(pred: Condition<Sub, Res, Act, Ctx>) {
    this.extraConditionPred = pred;
    return this;
  }

  build(): Policy<Sub, Res, Act, Ctx> {
    const {
      subjectPred,
      resPred,
      actionPred,
      ctxPred,
      _name: name,
      _effect: effect,
      extraConditionPred,
    } = this;

    const combinedPredicate = (
      subject: Sub,
      resource: Res,
      action: Act,
      context: Ctx
    ): Effect.Effect<boolean> =>
      Effect.gen(function* () {
        return (
          (subjectPred === null || (yield* subjectPred(subject))) &&
          (resPred === null || (yield* resPred(resource))) &&
          (actionPred === null || (yield* actionPred(action))) &&
          (ctxPred === null || (yield* ctxPred(context))) &&
          (extraConditionPred === null ||
            (yield* extraConditionPred({ subject, resource, action, context })))
        );
      });

    return transformInternalPolicy({
      name,
      effect,
      predicate: combinedPredicate,
    });
  }
}

// ---- RBAC ----

interface RoleBasedPolicy<Subject, Resource, Action, Context, Role>
  extends Policy<Subject, Resource, Action, Context> {
  requiredRolesResolver: (res: Resource, act: Action) => Effect.Effect<Role[]>;
  userRolesResolver: (subject: Subject) => Effect.Effect<Role[]>;
  name: string;
}

/**
 * Creates a Role-Based Access Control policy.
 * Resolvers now return Effect<Role[]> instead of Role[] | Promise<Role[]>.
 */
function buildRbacPolicy<Sub, Res, Act, Ctx, Role>({
  requiredRolesResolver,
  userRolesResolver,
  name = 'RbacPolicy',
}: {
  requiredRolesResolver: (res: Res, act: Act) => Effect.Effect<Role[]>;
  userRolesResolver: (sub: Sub) => Effect.Effect<Role[]>;
  name?: string;
}): RoleBasedPolicy<Sub, Res, Act, Ctx, Role> {
  const policyType = name;
  const evaluateAccess: EvaluateAccess<Sub, Res, Act, Ctx> = ({
    subject,
    resource,
    action,
  }) =>
    Effect.gen(function* () {
      const requiredRoles: Role[] = yield* requiredRolesResolver(resource, action);
      const userRoles: Role[] = yield* userRolesResolver(subject);
      const hasRole: boolean = requiredRoles.some((role) => userRoles.includes(role));
      if (hasRole) {
        return new GrantedAccessResult({
          policyType: name,
          reason: 'User has required role',
        });
      }
      return new DeniedAccessResult({
        policyType: name,
        reason: "User doesn't have required role",
      });
    });

  return Object.freeze({
    name: policyType,
    evaluateAccess,
    requiredRolesResolver,
    userRolesResolver,
  });
}

// ---- ABAC ----

interface AttributeBasedPolicy<Subject, Resource, Action, Context>
  extends Policy<Subject, Resource, Action, Context> {
  condition: Condition<Subject, Resource, Action, Context>;
}

/**
 * Creates an Attribute-Based Access Control policy.
 * Condition now returns Effect<boolean> instead of boolean | Promise<boolean>.
 */
function buildAbacPolicy<Sub, Res, Act, Ctx>({
  condition,
  name = 'AbacPolicy',
}: {
  condition: Condition<Sub, Res, Act, Ctx>;
  name?: string;
}): AttributeBasedPolicy<Sub, Res, Act, Ctx> {
  const policyType = name;
  const evaluateAccess: EvaluateAccess<Sub, Res, Act, Ctx> = ({
    subject,
    resource,
    action,
    context,
  }) =>
    Effect.gen(function* () {
      const conditionMet: boolean = yield* condition({
        subject,
        resource,
        action,
        context,
      });
      if (conditionMet) {
        return new GrantedAccessResult({
          policyType,
          reason: 'Condition evaluated to true',
        });
      }
      return new DeniedAccessResult({
        policyType,
        reason: 'Condition evaluated to false',
      });
    });

  return Object.freeze({ name: policyType, evaluateAccess, condition });
}

// ---- ReBAC ----

interface RelationshipBasedPolicy<Sub, Res, Act, Ctx>
  extends Policy<Sub, Res, Act, Ctx> {
  readonly relationship: string;
  readonly resolver: RelationshipResolver<Sub, Res>;
  name: string;
}

/**
 * Creates a Relationship-Based Access Control policy.
 * Resolver now returns Effect<boolean> instead of boolean | Promise<boolean>.
 */
function buildRebacPolicy<Sub, Res, Act, Ctx>({
  relationship,
  resolver,
  name = 'RebacPolicy',
}: {
  relationship: string;
  resolver: RelationshipResolver<Sub, Res>;
  name?: string;
}): RelationshipBasedPolicy<Sub, Res, Act, Ctx> {
  const policyType = name;
  const evaluateAccess: EvaluateAccess<Sub, Res, Act, Ctx> = ({
    subject,
    resource,
  }) =>
    Effect.gen(function* () {
      const hasRelationship: boolean = yield* resolver({
        subject,
        resource,
        relationship,
      });
      if (hasRelationship) {
        return new GrantedAccessResult({
          policyType,
          reason: `Subject has ${relationship} relationship with resource`,
        });
      }
      return new DeniedAccessResult({
        policyType,
        reason: `Subject does not have ${relationship} relationship with resource`,
      });
    });

  return Object.freeze({
    name: policyType,
    evaluateAccess,
    resolver,
    relationship,
  });
}

// ---- AND Policy ----

interface AndPolicy<Sub, Res, Act, Ctx> extends Policy<Sub, Res, Act, Ctx> {
  readonly policies: Policy<Sub, Res, Act, Ctx>[];
  name: string;
}

/**
 * Creates a policy that requires all sub-policies to grant access.
 */
function buildAndPolicy<Sub, Res, Act, Ctx>({
  policies,
  name = 'AndPolicy',
}: {
  policies: Policy<Sub, Res, Act, Ctx>[];
  name?: string;
}): AndPolicy<Sub, Res, Act, Ctx> {
  if (!policies.length) {
    throw new Error('AndPolicy must have at least one policy');
  }

  const policyType = name;
  const evaluateAccess: EvaluateAccess<Sub, Res, Act, Ctx> = (args) =>
    Effect.gen(function* () {
      const results: PolicyEvalResult[] = [];
      for (const policy of policies) {
        const result = yield* policy.evaluateAccess(args);
        results.push(result);

        if (!result.isGranted()) {
          return new CombinedResult({
            policyType,
            reason: null,
            outcome: false,
            operation: CombineOp.And,
            children: results,
          });
        }
      }
      return new CombinedResult({
        policyType,
        reason: null,
        outcome: true,
        operation: CombineOp.And,
        children: results,
      });
    });

  return Object.freeze({
    name: policyType,
    evaluateAccess,
    policies: [...policies],
  });
}

// ---- OR Policy ----

interface OrPolicy<Sub, Res, Act, Ctx> extends Policy<Sub, Res, Act, Ctx> {
  readonly policies: Policy<Sub, Res, Act, Ctx>[];
  name: string;
}

/**
 * Creates a policy that grants access if any sub-policy grants access.
 */
function buildOrPolicy<Sub, Res, Act, Ctx>({
  policies,
  name = 'OrPolicy',
}: {
  policies: Policy<Sub, Res, Act, Ctx>[];
  name?: string;
}): OrPolicy<Sub, Res, Act, Ctx> {
  if (!policies.length) {
    throw new Error('OrPolicy must have at least one policy');
  }

  const policyType = name;
  const evaluateAccess: EvaluateAccess<Sub, Res, Act, Ctx> = (args) =>
    Effect.gen(function* () {
      const results: PolicyEvalResult[] = [];
      for (const policy of policies) {
        const result = yield* policy.evaluateAccess(args);
        results.push(result);

        if (result.isGranted()) {
          return new CombinedResult({
            policyType,
            reason: null,
            outcome: true,
            operation: CombineOp.Or,
            children: results,
          });
        }
      }
      return new CombinedResult({
        policyType,
        reason: null,
        outcome: false,
        operation: CombineOp.Or,
        children: results,
      });
    });

  return Object.freeze({
    name: policyType,
    evaluateAccess,
    policies: [...policies],
  });
}

// ---- NOT Policy ----

interface NotPolicy<Sub, Res, Act, Ctx> extends Policy<Sub, Res, Act, Ctx> {
  readonly policy: Policy<Sub, Res, Act, Ctx>;
  name: string;
}

/**
 * Creates a policy that inverts the result of another policy.
 */
function buildNotPolicy<Sub, Res, Act, Ctx>({
  policy,
  name = 'NotPolicy',
}: {
  policy: Policy<Sub, Res, Act, Ctx>;
  name?: string;
}): NotPolicy<Sub, Res, Act, Ctx> {
  const policyType = name;
  const evaluateAccess: EvaluateAccess<Sub, Res, Act, Ctx> = (args) =>
    Effect.gen(function* () {
      const result = yield* policy.evaluateAccess(args);
      return new CombinedResult({
        policyType,
        reason: null,
        outcome: !result.isGranted(),
        operation: CombineOp.Not,
        children: [result],
      });
    });

  return Object.freeze({
    name: policyType,
    evaluateAccess,
    policy,
  });
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
  CombineOp,
  type Condition,
  type EvaluateAccess,
  type IntendedEffect,
  NoPoliciesError,
  PermissionChecker,
  type Policy,
  PolicyBuilder,
  PolicyEffect,
  type PolicyEvalResult,
  type RelationshipResolver,
};
