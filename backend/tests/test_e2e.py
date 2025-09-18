"""End to end browser tests.

These tests drive the real frontend against the real backend with a real
browser.  They require a running frontend (``npm run dev``) and backend
(``uvicorn app.main:app``) or the Docker Compose stack.

They are skipped when the services are not reachable so that the rest of the
suite still runs on a bare machine.

Run them with::

    pytest tests/test_e2e.py -m e2e \\
        --frontend-url http://127.0.0.1:5173 \\
        --backend-url http://127.0.0.1:8000
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.e2e

FRONTEND_URL = os.getenv("SAXIS_E2E_FRONTEND_URL", "http://127.0.0.1:5173")
BACKEND_URL = os.getenv("SAXIS_E2E_BACKEND_URL", "http://127.0.0.1:8000")
USERNAME = os.getenv("SAXIS_E2E_USERNAME", "admin")
PASSWORD = os.getenv("SAXIS_E2E_PASSWORD", "admin-change-me")


def _services_available() -> bool:
    import httpx

    for url in (f"{BACKEND_URL}/health", f"{FRONTEND_URL}/"):
        try:
            response = httpx.get(url, timeout=5)
            if response.status_code >= 500:
                return False
        except Exception:
            return False
    return True


pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(not _services_available(), reason="The application is not running."),
]


@pytest.fixture(scope="module")
def browser():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        instance = playwright.chromium.launch(args=["--no-sandbox"])
        yield instance
        instance.close()


@pytest.fixture()
def page(browser):
    context = browser.new_context(viewport={"width": 1600, "height": 1000})
    page = context.new_page()
    page.set_default_timeout(45_000)
    yield page
    context.close()


def _login(page) -> None:
    page.goto(f"{FRONTEND_URL}/login", wait_until="networkidle")
    page.fill("#username", USERNAME)
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(f"{FRONTEND_URL}/", timeout=45_000)


def test_login_and_overview(page) -> None:
    _login(page)
    page.wait_for_selector("text=Total executions", timeout=30_000)
    assert page.locator("text=Security operations overview").count() == 1


def test_denied_action_is_explained(page) -> None:
    _login(page)
    page.goto(f"{FRONTEND_URL}/tools", wait_until="networkidle")
    page.wait_for_selector("text=Registered tools", timeout=30_000)
    page.fill("#tool-args", '{\n  "path": "protected/secret.txt"\n}')
    page.click("button:has-text('Invoke')")
    page.wait_for_selector("text=deny-protected-workspace-paths", timeout=30_000)


def test_attack_laboratory_reports_no_successful_attack(page) -> None:
    _login(page)
    page.goto(f"{FRONTEND_URL}/attack-lab", wait_until="networkidle")
    page.wait_for_selector("text=Attack success rate", timeout=30_000)
    page.click("button:has-text('Run the whole catalogue')")
    for _ in range(120):
        page.wait_for_timeout(1000)
        rows = page.locator("table tbody tr").count()
        if rows >= 30:
            break
    page.wait_for_timeout(1500)
    assert page.locator("text=passed").count() > 20


def test_audit_chain_verifies(page) -> None:
    _login(page)
    page.goto(f"{FRONTEND_URL}/audit", wait_until="networkidle")
    page.wait_for_selector("text=Audit trail", timeout=30_000)
    page.wait_for_timeout(1500)
    assert page.locator("text=chain intact").count() == 1
