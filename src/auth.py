from __future__ import annotations

from collections.abc import Generator
from typing import TYPE_CHECKING

import httpx
from soar_sdk.exceptions import ActionFailure

from .consts import CISCOUMBRELLA_CONFIG_PARAMS_REQUIRED

if TYPE_CHECKING:
    from .asset import Asset


class QueryParamAuth(httpx.Auth):
    """Auth flow that attaches the Cisco Umbrella customer key as a query
    parameter (``customerKey``) rather than an ``Authorization`` header.
    """

    def __init__(self, key: str) -> None:
        self._key = key

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response]:
        request.url = request.url.copy_merge_params({"customerKey": self._key})
        yield request


def resolve_ciscoumbrella_auth(asset: Asset) -> httpx.Auth:
    """Cisco Umbrella only supports a single static credential (customer key),
    sent as a query parameter on every request.
    """
    if asset.customer_key:
        return QueryParamAuth(asset.customer_key)
    raise ActionFailure(CISCOUMBRELLA_CONFIG_PARAMS_REQUIRED)
