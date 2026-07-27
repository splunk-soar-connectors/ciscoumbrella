from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from soar_sdk.abstract import SOARClient
from soar_sdk.logging import getLogger

from ..asset import Asset
from ..client import call_ciscoumbrella
from ..consts import (
    CISCOUMBRELLA_API_BASE_URL,
    CISCOUMBRELLA_CONNECTING_TO_MSG,
    CISCOUMBRELLA_ENDPOINT_DOMAINS,
    CISCOUMBRELLA_MSG_GET_DOMAIN_LIST_TEST,
    CISCOUMBRELLA_TEST_CONNECTIVITY_FAILED_MSG,
    CISCOUMBRELLA_TEST_CONNECTIVITY_PASSED_MSG,
    CISCOUMBRELLA_USING_BASE_URL,
)

if TYPE_CHECKING:
    from soar_sdk.app import App

logger = getLogger()


def run_test_connectivity(soar: SOARClient, asset: Asset, *, app: App | None = None) -> None:
    host = urlsplit(CISCOUMBRELLA_API_BASE_URL).netloc
    logger.progress(CISCOUMBRELLA_USING_BASE_URL.format(base_url=CISCOUMBRELLA_API_BASE_URL))
    logger.progress(CISCOUMBRELLA_CONNECTING_TO_MSG.format(host=host))
    logger.progress(CISCOUMBRELLA_MSG_GET_DOMAIN_LIST_TEST)

    try:
        call_ciscoumbrella(
            "GET", CISCOUMBRELLA_ENDPOINT_DOMAINS, asset, params={"page": 1, "limit": 1}
        )
    except Exception:
        logger.progress(CISCOUMBRELLA_TEST_CONNECTIVITY_FAILED_MSG)
        raise

    logger.progress(CISCOUMBRELLA_TEST_CONNECTIVITY_PASSED_MSG)
