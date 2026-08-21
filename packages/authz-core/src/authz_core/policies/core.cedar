// Visibility probes. These exist so requires() can ask "can you see this at all?"
// before asking "may you do X to it", which is what makes 404-not-403 possible.
// Each reads an attribute its OWN resource type declares: borrowing WorkflowList
// for an Organization errors, because Organization has no can_view (verified).
@id("org-view")
permit(principal, action == Action::"OrgView", resource)
when { principal in resource.org };

@id("team-view")
permit(principal, action == Action::"TeamView", resource)
when { principal in resource.can_view };

@id("cap-view")
permit(principal, action in [Action::"WorkflowView", Action::"WorkflowList"], resource)
when { principal in resource.can_view };

@id("cap-run")
permit(principal, action == Action::"WorkflowRun", resource)
when { principal in resource.can_run };

@id("cap-edit")
permit(principal, action in [Action::"WorkflowCreate", Action::"WorkflowUpdate"], resource)
when { principal in resource.can_edit };

@id("cap-export")
permit(principal, action == Action::"WorkflowExport", resource)
when { principal in resource.can_export };

@id("cap-protect-export")
permit(principal, action == Action::"WorkflowProtectExport", resource)
when { principal in resource.can_protect_export };

@id("cap-delete")
permit(principal, action in [Action::"WorkflowDelete", Action::"TeamDelete"], resource)
when { principal in resource.can_delete };

@id("cap-manage-members")
permit(principal, action in [Action::"TeamAddMember", Action::"TeamRemoveMember",
                             Action::"TeamChangeRole"], resource)
when { principal in resource.can_manage_members };

@id("cap-create-team")
permit(principal, action == Action::"TeamCreate", resource)
when { principal in resource.can_create_team };

@id("cap-manage-roles")
permit(principal, action in [Action::"RoleCreate", Action::"RoleDelete"], resource)
when { principal in resource.can_manage_roles };

@id("cap-manage-api-keys")
permit(principal, action in [Action::"ApiKeyCreate", Action::"ApiKeyRevoke"], resource)
when { principal in resource.can_manage_api_keys };

// Scoped to an enumerated action GROUP, never `action` unconstrained: an open
// permit would silently confer every future action on the most privileged role.
@id("org-super-admin-full")
permit(principal, action in Action::"OrgAdministrable", resource)
when { principal in resource.org_admins };
