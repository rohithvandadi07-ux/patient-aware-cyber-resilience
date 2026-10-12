"""Small shared Playwright locator helpers for the Scenario A/B E2E tests.

`frontend/src/components/Panel.tsx` renders every incident-detail sub-panel
as a `<section>` with an `<h2>{title}</h2>` -- `panel_section` scopes a
locator to one specific panel via its exact heading text, rather than
`section.filter(has_text=...)`'s substring matching, which would also match,
e.g., the Agent Activity panel when scoping for "Recovery" (its own body
lists a "Recovery Verification" agent row).
"""

from __future__ import annotations

from playwright.sync_api import Locator, Page


def panel_section(page: Page, title: str) -> Locator:
    return page.locator("section", has=page.get_by_role("heading", name=title, exact=True))
