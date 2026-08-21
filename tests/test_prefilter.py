"""The pre-filter is an optimisation and never the authority.

A pre-filter that is too BROAD is merely wasteful. One that is too NARROW silently
hides rows the policy would have allowed — a correctness bug. Only this test
distinguishes them.

NOTE on the corpus import: the brief specifies `from tests.helpers.corpus import
corpus`, but this repo's `packages/authz-core/tests` directory is itself a package
named `tests` (it has an `__init__.py`). Since a single pytest session collects both
test trees, only one `tests` package can exist in `sys.modules` at a time — adding a
root `tests/__init__.py` makes pytest's own collection of the two `tests/conftest.py`
files collide (`ImportPathMismatchError`), breaking the whole suite. `tests/helpers`
is therefore imported as a bare top-level package instead: pytest puts `tests/` on
`sys.path` when collecting files directly inside it (no `__init__.py` there), which
makes `tests/helpers/` importable as `helpers` with no naming conflict.
"""

from authz_core import Capability

from app.infra.entity_provider import CapabilitySlice
from app.infra.prefilter import build_workflow_prefilter


def test_prefilter_includes_teams_with_view() -> None:
    slice_ = CapabilitySlice(
        team_caps={"team-1": {Capability.VIEW}, "team-2": {Capability.RUN}},
        org_caps={},
    )
    spec = build_workflow_prefilter(slice_)
    assert spec.team_ids == {"team-1"}
    assert spec.org_ids == set()


def test_super_admin_prefilter_covers_the_whole_org() -> None:
    slice_ = CapabilitySlice(team_caps={}, org_caps={"org-1": {Capability.MANAGE_ORG}})
    spec = build_workflow_prefilter(slice_)
    assert spec.org_ids == {"org-1"}


def test_prefilter_is_a_superset_of_what_the_engine_allows() -> None:
    """Containment property: every row the engine would allow must survive the filter."""
    from authz_core import Action, AuthzContext, PolicyEngine
    from helpers.corpus import corpus  # tests/helpers/corpus.py, see module docstring

    engine = PolicyEngine()
    for principal, slice_, cap_slice, workflows in corpus():
        spec = build_workflow_prefilter(cap_slice)
        prefiltered = {w.ref.id for w in workflows if spec.matches(w)}
        decisions = engine.authorize_batch(
            principal=principal,
            action=Action.WORKFLOW_VIEW,
            resources=tuple(w.ref for w in workflows),
            slice_=slice_,
            context=AuthzContext(auth_method="jwt"),
        )
        allowed = {w.ref.id for w, d in zip(workflows, decisions, strict=True) if d.allowed}
        assert allowed <= prefiltered, f"pre-filter is too narrow — hides {allowed - prefiltered}"


def test_empty_slice_yields_a_filter_that_matches_nothing() -> None:
    spec = build_workflow_prefilter(CapabilitySlice())
    assert spec.is_empty()
