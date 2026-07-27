from soar_sdk.app import App

from .block_domain import block_domain
from .list_blocked_domains import ListBlockedDomainsSummary, list_blocked_domains
from .unblock_domain import unblock_domain


def register_actions(app: App) -> App:
    app.register_action(
        action=list_blocked_domains,
        description="Queries Cisco for the blocked domain list",
        action_type="investigate",
        render_as="table",
        summary_type=ListBlockedDomainsSummary,
    )
    app.register_action(
        action=block_domain,
        description="Block a domain",
        action_type="contain",
        read_only=False,
        render_as="table",
        verbose=(
            "Cisco has many safeguards in place before adding a domain to a block "
            "list. These are present to protect against accidentally submitting "
            "domains for highly popular or known sites like google.com. If the "
            "'disable_safeguards' parameter is set to True (or checked), those "
            "safeguards will be bypassed. This could potentially allow adding a "
            "well-known domain like google.com to a domain block list."
        ),
    )
    app.register_action(
        action=unblock_domain,
        description="Unblock a domain",
        action_type="correct",
        read_only=False,
        render_as="table",
    )
    return app
