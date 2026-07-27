from __future__ import annotations

import time

import httpx
from soar_sdk.exceptions import ActionFailure

from .asset import Asset
from .auth import resolve_ciscoumbrella_auth
from .consts import (
    CISCOUMBRELLA_API_BASE_URL,
    CISCOUMBRELLA_ERR_FROM_SERVER,
    CISCOUMBRELLA_ERR_INVALID_JSON,
    CISCOUMBRELLA_ERR_SERVER_CONNECTION,
    CISCOUMBRELLA_NON_NEG_INT_MSG,
    CISCOUMBRELLA_NON_NEG_NON_ZERO_INT_MSG,
    CISCOUMBRELLA_VALID_INT_MSG,
    DEFAULT_TIMEOUT,
)

CISCOUMBRELLA_DEFAULT_HEADERS: dict[str, str] = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}


def validate_integer(
    value: float | None, param_label: str, *, allow_zero: bool = False
) -> int | None:
    """Port of the legacy connector's ``_validate_integer`` — raises
    ``ActionFailure`` instead of returning a status tuple.
    """
    if value is None:
        return None

    try:
        if not float(value).is_integer():
            raise ActionFailure(CISCOUMBRELLA_VALID_INT_MSG.format(param=param_label))
        int_value = int(value)
    except (TypeError, ValueError) as exc:
        raise ActionFailure(
            CISCOUMBRELLA_VALID_INT_MSG.format(param=param_label)
        ) from exc

    if int_value < 0:
        raise ActionFailure(CISCOUMBRELLA_NON_NEG_INT_MSG.format(param=param_label))
    if not allow_zero and int_value == 0:
        raise ActionFailure(
            CISCOUMBRELLA_NON_NEG_NON_ZERO_INT_MSG.format(param=param_label)
        )

    return int_value


def _get_error_message(resp_json: dict | None, response: httpx.Response) -> str:
    if not resp_json:
        return ""

    message = resp_json.get("message", "")

    if response.status_code == 500:
        message += ". The service may be down or your license may have expired."

    return message


def call_ciscoumbrella(
    method: str,
    endpoint: str,
    asset: Asset,
    *,
    params: dict | None = None,
    json: object | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = True,
) -> httpx.Response:
    """Port of the legacy connector's ``_make_rest_call``: retries on HTTP
    429 up to ``asset.retry_count`` times (waiting ``asset.retry_wait_time``
    seconds between attempts), and never surfaces a raw connection
    exception — it can embed the ``customerKey`` query parameter — only the
    generic connection-failure message.
    """
    url = f"{CISCOUMBRELLA_API_BASE_URL}{endpoint}"
    headers = {**CISCOUMBRELLA_DEFAULT_HEADERS, **(extra_headers or {})}
    auth = resolve_ciscoumbrella_auth(asset)  # raises ActionFailure when unconfigured

    retry_count = (
        validate_integer(asset.retry_count, "'Maximum attempts to retry the API call' asset configuration")
        or 0
    )
    retry_wait_time = validate_integer(
        asset.retry_wait_time, "'Delay in seconds between retries' asset configuration"
    ) or 0

    response: httpx.Response | None = None
    for retry in range(retry_count + 1):
        try:
            with httpx.Client(timeout=timeout, verify=verify) as client:
                response = client.request(
                    method=method,
                    url=url,
                    auth=auth,
                    headers=headers,
                    params=params,
                    json=json,
                )
        except httpx.RequestError as exc:
            raise ActionFailure(CISCOUMBRELLA_ERR_SERVER_CONNECTION) from exc

        if response.status_code != 429:
            break
        if retry != retry_count:
            time.sleep(retry_wait_time)

    if response.status_code == 204:
        return response

    try:
        resp_json = response.json()
    except ValueError as exc:
        raise ActionFailure(CISCOUMBRELLA_ERR_INVALID_JSON) from exc

    if response.status_code == 202:
        return response

    if response.status_code != httpx.codes.OK:
        raise ActionFailure(
            CISCOUMBRELLA_ERR_FROM_SERVER.format(
                status=response.status_code,
                message=_get_error_message(resp_json, response),
            )
        )

    return response
