def test_playwright_sync_api_import():
    from playwright.sync_api import sync_playwright

    assert callable(sync_playwright)
