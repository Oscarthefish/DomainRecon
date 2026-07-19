from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from .models import ScanResult


async def capture_screenshots(result: ScanResult, output: Path, limit: int = 20) -> int:
    """Capture live web assets when the optional Playwright runtime is installed."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return 0
    targets = [asset for asset in result.assets.values() if asset.kind == "url"][:limit]
    if not targets:
        return 0
    destination = output / "screenshots"
    destination.mkdir(parents=True, exist_ok=True)
    captured = 0
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": 1440, "height": 900})
            for asset in targets:
                filename = f"{captured + 1:03d}-{asset.root_domain.replace('.', '-')}.png"
                try:
                    await page.goto(asset.value, wait_until="domcontentloaded", timeout=15_000)
                    await page.screenshot(path=destination / filename, full_page=False)
                except Exception:
                    continue
                attributes = dict(asset.attributes)
                attributes["screenshot"] = f"screenshots/{filename}"
                result.assets[asset.key] = replace(asset, attributes=attributes)
                captured += 1
            await browser.close()
    except Exception as exc:
        result.errors.append(f"screenshots: {type(exc).__name__}: {exc}")
    return captured
