from __future__ import annotations

from typing import TYPE_CHECKING

from soar_sdk.exceptions import ActionFailure

from ..client import call_ciscoumbrella
from ..consts import (
    CISCOUMBRELLA_DEFAULT_DOMAIN_LIMIT,
    CISCOUMBRELLA_DEFAULT_MAX_PAGES,
    CISCOUMBRELLA_ENDPOINT_DOMAINS,
    CISCOUMBRELLA_PAGINATION_EXCEEDED_MSG,
)

if TYPE_CHECKING:
    from ..asset import Asset


def _paginate_domains(asset: Asset, *, limit: int | None = None) -> list[dict]:
    """Port of the legacy connector's ``_paginator``: walks ``/domains`` page
    by page until ``meta.next`` is absent, a hard cap of
    ``CISCOUMBRELLA_DEFAULT_MAX_PAGES`` pages is hit (a hard error, not a
    silent truncation), or ``limit`` results have accumulated. ``limit`` is a
    client-side post-filter applied after accumulating full pages, matching
    the legacy behavior exactly — it is not sent as a request-level limit.
    """
    data: list[dict] = []
    page = 1
    while True:
        response = call_ciscoumbrella(
            "GET",
            CISCOUMBRELLA_ENDPOINT_DOMAINS,
            asset,
            params={"limit": CISCOUMBRELLA_DEFAULT_DOMAIN_LIMIT, "page": page},
        )
        body = response.json()
        data.extend(body.get("data", []))

        if limit and len(data) >= limit:
            return data[:limit]

        if not body.get("meta", {}).get("next"):
            break

        if page >= CISCOUMBRELLA_DEFAULT_MAX_PAGES:
            raise ActionFailure(
                CISCOUMBRELLA_PAGINATION_EXCEEDED_MSG.format(
                    max_pages=CISCOUMBRELLA_DEFAULT_MAX_PAGES
                )
            )

        page += 1

    return data
