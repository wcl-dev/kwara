"""kwara — operator attribution and digital evidence for adtech forensics.

Import the pieces you need; nothing is re-exported here on purpose, so
importing the package stays cheap and does not drag in Playwright, the MCP
SDK, or a database connection as a side effect.

    from kwara.cli import build_parser
    from kwara.clustering_infra import shared_ad_accounts

The command line is the source of truth for automation:

    python -m kwara.cli --help
"""

__version__ = "0.9.0"
