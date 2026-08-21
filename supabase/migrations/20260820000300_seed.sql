insert into capabilities (name, description) values
    ('view',            'See a workflow'),
    ('run',             'Execute a workflow'),
    ('edit',            'Create or modify a workflow'),
    ('export',          'Publish a workflow'),
    ('protect_export',  'Set password or org-only restriction on a published workflow'),
    ('delete',          'Delete a workflow or team'),
    ('manage_members',  'Add, remove, and re-role team members'),
    ('create_team',     'Create a team within the organization'),
    ('manage_org',      'Full administrative control of the organization'),
    ('manage_roles',    'Create and delete custom roles'),
    ('manage_api_keys', 'Mint and revoke API keys');

insert into api_key_scopes (name, description) values
    ('workflow:run',  'Execute workflows'),
    ('workflow:read', 'List and view workflows');

insert into roles (id, org_id, name, scope, description) values
    ('00000000-0000-0000-0000-000000000001', null, 'member',      'org',  'Regular organization member'),
    ('00000000-0000-0000-0000-000000000002', null, 'super_admin', 'org',  'Full control of the organization'),
    ('00000000-0000-0000-0000-000000000011', null, 'viewer',      'team', 'Can see and run team resources'),
    ('00000000-0000-0000-0000-000000000012', null, 'editor',      'team', 'Can also edit and publish'),
    ('00000000-0000-0000-0000-000000000013', null, 'admin',       'team', 'Can also manage members and protection');

insert into role_capabilities (role_id, capability) values
    ('00000000-0000-0000-0000-000000000001', 'create_team'),
    ('00000000-0000-0000-0000-000000000002', 'create_team'),
    ('00000000-0000-0000-0000-000000000002', 'manage_org'),
    ('00000000-0000-0000-0000-000000000002', 'manage_roles'),
    ('00000000-0000-0000-0000-000000000002', 'manage_api_keys'),
    ('00000000-0000-0000-0000-000000000011', 'view'),
    ('00000000-0000-0000-0000-000000000011', 'run'),
    ('00000000-0000-0000-0000-000000000012', 'view'),
    ('00000000-0000-0000-0000-000000000012', 'run'),
    ('00000000-0000-0000-0000-000000000012', 'edit'),
    ('00000000-0000-0000-0000-000000000012', 'export'),
    ('00000000-0000-0000-0000-000000000013', 'view'),
    ('00000000-0000-0000-0000-000000000013', 'run'),
    ('00000000-0000-0000-0000-000000000013', 'edit'),
    ('00000000-0000-0000-0000-000000000013', 'export'),
    ('00000000-0000-0000-0000-000000000013', 'protect_export'),
    ('00000000-0000-0000-0000-000000000013', 'delete'),
    ('00000000-0000-0000-0000-000000000013', 'manage_members');
