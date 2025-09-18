#!/usr/bin/env python3
"""Capture real screenshots of the running application.

The script drives the *running* application with Playwright: it signs in,
performs real workflows (an authorised analysis, a denied action, an approval
and a full prompt-injection laboratory run) and stores the resulting images
under ``docs/images/``.

Usage::

    python scripts/capture_screenshots.py \
        --frontend http://127.0.0.1:5173 \
        --backend http://127.0.0.1:8000 \
        --username admin --password admin-change-me \
        --output docs/images

Every screenshot is taken from the live application; nothing is mocked.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, sync_playwright


def log(message: str) -> None:
    print(f"[screenshot] {message}", flush=True)


def capture(page: Page, output: Path, name: str, full_page: bool = True) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    path = output / f"{name}.png"
    if full_page:
        # A sticky header would be painted in the middle of a full page
        # screenshot; make it static for the capture only.
        page.add_style_tag(content="header.sticky { position: static !important; }")
    page.screenshot(path=str(path), full_page=full_page)
    log(f"saved {path}")
    return path


def settle(page: Page, selector: str | None = None, timeout: int = 30_000) -> None:
    """Wait until the page has actually rendered its data."""
    if selector:
        try:
            page.wait_for_selector(selector, timeout=timeout)
        except PlaywrightError as exc:  # pragma: no cover - diagnostics only
            log(f"warning: selector {selector!r} did not appear: {exc}")
    page.wait_for_timeout(700)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend", default="http://127.0.0.1:5173")
    parser.add_argument("--backend", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin-change-me")
    parser.add_argument("--output", default="docs/images")
    parser.add_argument("--theme", default="dark", choices=["dark", "light"])
    args = parser.parse_args()

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(args=["--no-sandbox"])
        context = browser.new_context(
            viewport={"width": 1600, "height": 1000},
            device_scale_factor=1,
            color_scheme=args.theme,
        )
        page = context.new_page()
        page.set_default_timeout(45_000)

        # ---------------------------------------------------------- login
        page.goto(f"{args.frontend}/login", wait_until="networkidle")
        if args.theme == "light":
            page.evaluate("localStorage.setItem('saxis-theme','light')")
            page.reload(wait_until="networkidle")
        capture(page, output, "01-login", full_page=False)

        page.fill("#username", args.username)
        page.fill("#password", args.password)
        page.click("button[type=submit]")
        page.wait_for_url(f"{args.frontend}/", timeout=45_000)
        settle(page, "text=Total executions")
        capture(page, output, "02-overview")

        # -------------------------------------------------------- workspace
        page.goto(f"{args.frontend}/workspace", wait_until="networkidle")
        settle(page, "text=Workspace path")
        capture(page, output, "03-workspace")

        # ------------------------------------------------------- agent run
        page.goto(f"{args.frontend}/agent", wait_until="networkidle")
        page.wait_for_timeout(600)
        page.click("button:has-text('New')")
        page.wait_for_timeout(1500)
        page.wait_for_selector("#agent-message:not([disabled])", timeout=30_000)
        page.fill(
            "#agent-message",
            "Read the file documents/quarterly-report.md and summarise the latency "
            "improvements for the engineering team.",
        )
        page.click("button:has-text('Run agent')")
        page.wait_for_timeout(1500)
        # The first run needs a human approval for the sandboxed write; wait
        # for the agent to finish either way.
        for _ in range(40):
            if page.locator("text=Run result").count() > 0:
                break
            page.wait_for_timeout(1000)
        page.wait_for_timeout(800)
        capture(page, output, "04-agent-run")

        # --------------------------------------------------------- approvals
        # Queue a request that needs a human decision so the queue is not
        # empty in the screenshot.
        page.goto(f"{args.frontend}/tools", wait_until="networkidle")
        settle(page, "text=Registered tools")
        page.fill("#tool-args", '{\n  "command": "ls documents"\n}')
        page.click("button:has-text('Invoke')")
        page.wait_for_timeout(2000)

        page.goto(f"{args.frontend}/approvals", wait_until="networkidle")
        settle(page, "text=Human approval queue")
        capture(page, output, "05-approvals")

        # -------------------------------------------------------- executions
        page.goto(f"{args.frontend}/executions", wait_until="networkidle")
        settle(page, "text=Filters")
        capture(page, output, "06-executions")

        # ---------------------------------------------------------- policies
        page.goto(f"{args.frontend}/policies", wait_until="networkidle")
        settle(page, "text=Rules in evaluation order")
        capture(page, output, "07-policies")

        # ------------------------------------------------------------- tools
        page.goto(f"{args.frontend}/tools", wait_until="networkidle")
        settle(page, "text=Registered tools")
        capture(page, output, "08-tools")

        # ----------------------------------------------------------- sandbox
        page.goto(f"{args.frontend}/sandbox", wait_until="networkidle")
        settle(page, "text=Enforced controls")
        capture(page, output, "09-sandbox")

        # ------------------------------------------------------- attack lab
        page.goto(f"{args.frontend}/attack-lab", wait_until="networkidle")
        settle(page, "text=Attack success rate")
        log("running the full attack laboratory")
        page.click("button:has-text('Run the whole catalogue')")
        for _ in range(90):
            page.wait_for_timeout(1000)
            if page.locator("text=Scenarios (").count() > 0:
                runs = page.locator("table tbody tr").count()
                if runs >= 30:
                    break
        page.wait_for_timeout(1500)
        capture(page, output, "10-attack-lab")

        # ------------------------------------------------------------- audit
        page.goto(f"{args.frontend}/audit", wait_until="networkidle")
        settle(page, "text=Audit trail")
        capture(page, output, "11-audit")

        # --------------------------------------------------------- providers
        page.goto(f"{args.frontend}/providers", wait_until="networkidle")
        settle(page, "text=Supported providers")
        capture(page, output, "12-providers")

        # ---------------------------------------------------------- settings
        page.goto(f"{args.frontend}/settings", wait_until="networkidle")
        settle(page, "text=Health")
        capture(page, output, "13-settings")

        # ------------------------------------------------- denial demo view
        log("demonstrating a denied action")
        page.goto(f"{args.frontend}/tools", wait_until="networkidle")
        settle(page, "text=Registered tools")
        page.fill(
            "#tool-args",
            '{\n  "path": "protected/secret.txt"\n}',
        )
        page.click("button:has-text('Invoke')")
        page.wait_for_timeout(1500)
        capture(page, output, "14-permission-denied")

        browser.close()

    log("all screenshots captured")
    return 0


if __name__ == "__main__":
    sys.exit(main())
