"""Second consumer of the authorization engine, with no HTTP in the path.

This exists to make the reusability claim demonstrable rather than asserted:
the same PolicyEngine, the same policies, the same decisions, invoked from a
terminal. Any service can embed authz-core the same way.
"""

import argparse
import sys

from authz_core import Action, AuthzContext, EngineError, PolicyEngine

# Reuses the same fixture builder the policy matrix uses, so CLI output and test
# expectations cannot drift apart.
sys.path.insert(0, "packages/authz-core/tests")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="authz", description="Query the policy engine.")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Evaluate one authorization decision")
    check.add_argument("--role", required=True)
    check.add_argument("--action", required=True)
    check.add_argument("--auth-method", default="jwt")
    check.add_argument("--exported", action="store_true")
    check.add_argument("--show-imports", action="store_true")

    args = parser.parse_args(argv)

    from conftest import build_slice  # type: ignore[import-not-found]

    principal, slice_ = build_slice(args.role, exported=args.exported)
    resource = slice_.resources[0].ref

    decision = PolicyEngine().authorize(
        principal=principal,
        action=Action(args.action),
        resource=resource,
        slice_=slice_,
        context=AuthzContext(auth_method=args.auth_method),
    )

    if args.show_imports:
        print("\n".join(sorted(m for m in sys.modules if "." not in m)))

    if isinstance(decision, EngineError):
        print(f"ERROR  {decision.message}")
        return 2
    verdict = "ALLOW" if decision.allowed else "DENY"
    print(f"{verdict}  {args.role} -> {args.action}   policy={decision.policy_id}")
    return 0 if decision.allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
