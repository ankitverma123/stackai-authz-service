from app.auth.workflow_token import issue_workflow_token, verify_workflow_token

SECRET = "s3cret-that-is-at-least-32-bytes-long"


def test_token_verifies_for_its_own_workflow() -> None:
    token = issue_workflow_token("wf-1", secret=SECRET, ttl_seconds=60)
    assert verify_workflow_token(token, "wf-1", secret=SECRET) is True


def test_token_is_scoped_to_one_workflow() -> None:
    """A token for wf-1 must not unlock wf-2."""
    token = issue_workflow_token("wf-1", secret=SECRET, ttl_seconds=60)
    assert verify_workflow_token(token, "wf-2", secret=SECRET) is False


def test_expired_token_is_rejected() -> None:
    token = issue_workflow_token("wf-1", secret=SECRET, ttl_seconds=-1)
    assert verify_workflow_token(token, "wf-1", secret=SECRET) is False


def test_token_signed_with_another_secret_is_rejected() -> None:
    token = issue_workflow_token(
        "wf-1", secret="other-secret-that-is-also-32-bytes+", ttl_seconds=60
    )
    assert verify_workflow_token(token, "wf-1", secret=SECRET) is False


def test_garbage_is_rejected_without_raising() -> None:
    assert verify_workflow_token("not-a-token", "wf-1", secret=SECRET) is False
