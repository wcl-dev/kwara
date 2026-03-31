def test_streamlit_installed():
    import streamlit as st

    assert getattr(st, "__version__", None)


def test_playwright_sync_api_import():
    from playwright.sync_api import sync_playwright

    assert callable(sync_playwright)
