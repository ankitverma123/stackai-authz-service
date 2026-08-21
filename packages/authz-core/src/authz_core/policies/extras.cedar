// THE BASELINE the three forbids below carve down. Cedar is default-deny, so
// without this every external execution is denied unconditionally and the brief's
// external-user requirement is dead. Unconditional by design; it does not violate
// the no-unconstrained-permit rule because the ACTION is pinned to one member —
// which is the constraint that rule is about. Every cap-* policy leaves principal
// and resource open in exactly the same way.
@id("public-run-exported")
permit(principal, action == Action::"WorkflowRunExported", resource);

@id("must-be-exported")
forbid(principal, action == Action::"WorkflowRunExported", resource)
unless { resource.exported };

@id("exported-requires-password")
forbid(principal, action == Action::"WorkflowRunExported", resource)
when { resource.password_protected && !context.password_verified };

@id("exported-org-members-only")
forbid(principal, action == Action::"WorkflowRunExported", resource)
when { resource.visibility == "org_only" && !(principal in resource.org) };

@id("api-key-no-governance")
forbid(principal, action in Action::"Governance", resource)
when { context.auth_method == "api_key" };

// Assumption #9 says API keys are "scoped to one org". Without this the key
// inherits the owner's ENTIRE multi-org capability slice, so a key minted in org A
// works on org B's workflows whenever the owner belongs to both. Verified: allows
// same-org, denies cross-org, denies when api_key_org is absent.
@id("api-key-single-org")
forbid(principal, action, resource)
when { context.auth_method == "api_key"
       && !((context has api_key_org) && resource.org == context.api_key_org) };

// Deliberately unconstrained. Safe precisely BECAUSE it is a forbid: a new action
// with no scope mapping is denied to machine identities until someone maps it.
@id("api-key-scope-check")
forbid(principal, action, resource)
when { context.auth_method == "api_key"
       && !((context has required_scope)
           && context.api_key_scopes.contains(context.required_scope)) };
