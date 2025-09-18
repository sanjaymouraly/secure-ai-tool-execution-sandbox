"""API integration tests: authentication, roles, CSRF and the tool pipeline."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_is_public(anonymous_client: TestClient) -> None:
    response = anonymous_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_ready_reports_the_sandbox(anonymous_client: TestClient) -> None:
    response = anonymous_client.get("/ready")
    assert response.status_code in (200, 503)
    payload = response.json()
    assert "sandbox" in payload
    assert "database" in payload


def test_protected_endpoints_require_authentication(anonymous_client: TestClient) -> None:
    for path in ("/api/v1/tools", "/api/v1/sessions", "/api/v1/audit/events", "/overview"):
        response = anonymous_client.get(path)
        assert response.status_code == 401, path


def test_login_with_wrong_password_is_rejected(anonymous_client: TestClient) -> None:
    response = anonymous_client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
    assert response.status_code == 401


def test_login_sets_session_cookies(anonymous_client: TestClient) -> None:
    response = anonymous_client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin-password-123"}
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["token_type"] == "bearer"
    assert payload["user"]["role"] == "admin"
    assert "sax_session" in response.cookies
    assert "sax_csrf" in response.cookies


def test_me_returns_the_current_user(client: TestClient) -> None:
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 200
    payload = response.json()
    assert payload["user"]["username"] == "admin"
    assert payload["permissions"]["can_approve"] is True


def test_tool_manifest_is_exposed(client: TestClient) -> None:
    response = client.get("/api/v1/tools")
    assert response.status_code == 200
    names = {tool["name"] for tool in response.json()["tools"]}
    assert {
        "list_files",
        "read_file",
        "search_files",
        "inspect_metadata",
        "calculate_hash",
        "execute_approved_command",
        "run_python_sandboxed",
        "create_artifact",
        "read_artifact",
        "request_permission",
        "view_execution_result",
    } <= names


def test_invoke_read_file(client: TestClient) -> None:
    response = client.post(
        "/api/v1/tools/read_file/invoke", json={"arguments": {"path": "documents/report.md"}}
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["decision"]["allowed"] is True


def test_invoke_protected_file_is_denied(client: TestClient) -> None:
    response = client.post(
        "/api/v1/tools/read_file/invoke", json={"arguments": {"path": "protected/secret.txt"}}
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "denied"
    assert payload["decision"]["rule_id"] == "deny-protected-workspace-paths"
    assert payload["decision"]["explanation"]


def test_invoke_unknown_tool_is_denied(client: TestClient) -> None:
    response = client.post("/api/v1/tools/not_a_tool/invoke", json={"arguments": {}})
    assert response.status_code == 200
    assert response.json()["status"] == "denied"


def test_invoke_with_invalid_arguments_is_denied(client: TestClient) -> None:
    response = client.post(
        "/api/v1/tools/read_file/invoke",
        json={"arguments": {"path": "documents/report.md", "unexpected": 1}},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "denied"


def test_policy_editor_requires_admin(anonymous_client: TestClient, container) -> None:
    from app.core.security import hash_password
    from app.db.models import User
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        user = User(
            username="plainuser",
            email="plain@test.local",
            hashed_password=hash_password("plain-password-123"),
            role="analyst",
            is_active=True,
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    response = anonymous_client.post(
        "/api/v1/auth/login", json={"username": "plainuser", "password": "plain-password-123"}
    )
    token = response.json()["access_token"]
    response = anonymous_client.post(
        "/api/v1/policies/current",
        json={"content": {"version": "1.0.0", "rules": []}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_policy_can_be_read(client: TestClient) -> None:
    response = client.get("/api/v1/policies/current")
    assert response.status_code == 200
    payload = response.json()
    assert payload["version"]
    assert len(payload["rules"]) > 5


def test_invalid_policy_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/policies/validate", json={"content": {"version": "1", "rules": [{"id": "x"}]}}
    )
    assert response.status_code == 200
    assert response.json()["valid"] is False


def test_approval_queue_and_decision(client: TestClient, container) -> None:
    created = client.post(
        "/api/v1/tools/execute_approved_command/invoke",
        json={"arguments": {"command": "ls documents"}},
    )
    assert created.status_code == 200
    payload = created.json()
    assert payload["status"] == "awaiting_approval"

    pending = client.get("/api/v1/approvals/pending")
    assert pending.status_code == 200
    approvals = pending.json()["approvals"]
    assert approvals

    decision = client.post(
        f"/api/v1/approvals/{approvals[0]['id']}/decision",
        json={"decision": "allow_once", "note": "approved for the test"},
    )
    assert decision.status_code == 200
    assert decision.json()["status"] == "approved"


def test_audit_events_are_recorded_and_verifiable(client: TestClient) -> None:
    client.post("/api/v1/tools/read_file/invoke", json={"arguments": {"path": "documents/report.md"}})
    response = client.get("/api/v1/audit/events?limit=10")
    assert response.status_code == 200
    events = response.json()["events"]
    assert events
    assert events[0]["action"].startswith("tool.")

    verification = client.get("/api/v1/audit/verify")
    assert verification.status_code == 200
    assert verification.json()["valid"] is True


def test_audit_export_requires_admin(container) -> None:
    from fastapi.testclient import TestClient

    from app.core.security import hash_password
    from app.db.models import User
    from app.db.session import SessionLocal
    from app.main import app

    db = SessionLocal()
    try:
        user = User(
            username="auditor",
            email="auditor@test.local",
            hashed_password=hash_password("auditor-password-123"),
            role="analyst",
            is_active=True,
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/login", json={"username": "auditor", "password": "auditor-password-123"}
        )
        token = response.json()["access_token"]
        response = client.get("/api/v1/audit/export?fmt=csv", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 403


def test_overview_uses_real_data(client: TestClient) -> None:
    client.post("/api/v1/tools/read_file/invoke", json={"arguments": {"path": "documents/report.md"}})
    response = client.get("/overview")
    assert response.status_code == 200
    payload = response.json()
    assert payload["executions"]["total"] >= 1
    assert payload["policy"]["version"]


def test_session_lifecycle(client: TestClient) -> None:
    created = client.post("/api/v1/sessions", json={"title": "Test session"})
    assert created.status_code == 201
    session_id = created.json()["id"]

    run = client.post(
        f"/api/v1/sessions/{session_id}/run",
        json={"message": "Read the file documents/report.md and summarise it."},
    )
    assert run.status_code == 200
    payload = run.json()
    assert payload["status"] in {"completed", "max_steps"}
    assert payload["final_text"]

    detail = client.get(f"/api/v1/sessions/{session_id}")
    assert detail.status_code == 200
    assert detail.json()["messages"]

    export = client.get(f"/api/v1/sessions/{session_id}/export")
    assert export.status_code == 200
    assert export.json()["session"]["id"] == session_id

    deleted = client.delete(f"/api/v1/sessions/{session_id}")
    assert deleted.status_code == 200


def test_csrf_is_enforced_for_cookie_authentication(container) -> None:
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        login = client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": "admin-password-123"}
        )
        assert login.status_code == 200
        # The cookie is sent automatically, but no CSRF header is present.
        response = client.post(
            "/api/v1/tools/read_file/invoke", json={"arguments": {"path": "documents/report.md"}}
        )
        assert response.status_code == 403
        assert "CSRF" in response.json()["detail"] or "csrf" in response.json()["detail"].lower()


def test_provider_types_are_listed(client: TestClient) -> None:
    response = client.get("/api/v1/providers/types")
    assert response.status_code == 200
    ids = {entry["id"] for entry in response.json()["types"]}
    assert {"openai", "anthropic", "openrouter", "custom", "ollama", "simulation"} <= ids


def test_security_headers_are_present(client: TestClient) -> None:
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in response.headers
