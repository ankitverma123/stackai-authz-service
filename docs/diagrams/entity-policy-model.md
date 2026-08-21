# Entity and policy model

Cedar never learns that roles exist. A `User`'s `Cap` parents are derived per
request by the `EntityProvider` from
`role_capabilities ⋈ team_memberships ⋈ org_memberships`; every `permit` policy
then tests parenthood (`principal in resource.can_X`), where `resource.can_X` is
itself a reference to a `Cap` entity. Solid arrows are entity **parents /
attributes**; dashed arrows show which attribute each policy family reads.

```mermaid
flowchart TD
    User -->|"Cap parents, derived per request from<br/>role_capabilities join team_memberships join org_memberships"| Cap["Cap entities<br/>e.g. edit:team:UUID, manage_org:org:UUID"]
    Organization -->|"org_admins attr = Cap manage_org:org:UUID"| Cap
    Team -->|parent| Organization
    Team -->|"can_view / can_edit / can_manage_members / can_delete attrs<br/>= Cap entity refs"| Cap
    Workflow -->|"can_view / can_run / can_edit / can_export /<br/>can_protect_export / can_delete attrs = Cap refs"| Cap
    Workflow -->|"org, team attrs = entity refs"| Team

    Cap -.->|"principal in resource.can_X"| CoreCedar["cap-view, cap-run, cap-edit, cap-export,<br/>cap-delete, cap-manage-members,<br/>cap-protect-export, cap-create-team,<br/>cap-manage-roles, cap-manage-api-keys"]
    Organization -.->|"principal in resource.org_admins<br/>(Action::OrgAdministrable group)"| SuperAdmin[org-super-admin-full]
    Workflow -.->|"resource.exported / visibility /<br/>password_protected + context.password_verified"| Extras["public-run-exported, must-be-exported,<br/>exported-requires-password,<br/>exported-org-members-only"]
```

**Why `Cap` and not a role check:** every seeded capability is bound by exactly
one `cap-*` policy, and roles never appear in Cedar at all — a new role is 2
`INSERT`s into `roles` / `role_capabilities`, zero policy edits. `org_admins` is
just the `manage_org` capability group, so super-admin is not a hardcoded special
case, and because it is scoped to *the resource's own* `org_admins`, a
super-admin's power stops at their organization's boundary automatically.
