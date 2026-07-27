from datetime import datetime, UTC

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params
from soar_sdk.shims.phantom.install_info import get_product_version

from ..asset import Asset
from ..client import call_ciscoumbrella
from ..consts import (
    CISCOUMBRELLA_ENDPOINT_EVENTS,
    CISCOUMBRELLA_ERR_GET_CONTAINER_INFO,
    CISCOUMBRELLA_EVENT_PROTOCOL_VERSION,
    CISCOUMBRELLA_EVENT_PROVIDER_NAME,
    CISCOUMBRELLA_LIST_UPDATED_WITH_GUID,
)


class BlockDomainParams(Params):
    domain: str = Param(
        description="Domain to block",
        primary=True,
        cef_types=["domain"],
        column_name="Domain",
    )
    disable_safeguards: bool | None = Param(
        description="Disable safeguards while blocking the domain"
    )


class BlockDomainOutput(ActionOutput):
    id: str = OutputField(column_name="ID")


def block_domain(
    params: BlockDomainParams, soar: SOARClient, asset: Asset
) -> BlockDomainOutput:
    container_id = soar.get_executing_container_id()
    try:
        container = soar.get(f"rest/container/{container_id}").json()
    except Exception as exc:
        raise ActionFailure(CISCOUMBRELLA_ERR_GET_CONTAINER_INFO) from exc

    domain = params.domain
    create_time = (
        datetime.strptime(container["create_time"], "%Y-%m-%dT%H:%M:%S.%fZ")
        .replace(tzinfo=UTC)
        .strftime("%Y-%m-%dT%H:%M:%S.0Z")
    )
    alert_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.0Z")

    event = {
        "deviceId": soar.get_asset_id(),
        "deviceVersion": get_product_version(),
        "eventTime": create_time,
        "alertTime": alert_time,
        "dstDomain": domain,
        "dstUrl": f"http://{domain}/",
        "protocolVersion": CISCOUMBRELLA_EVENT_PROTOCOL_VERSION,
        "providerName": CISCOUMBRELLA_EVENT_PROVIDER_NAME,
        "disableDstSafeguards": params.disable_safeguards or False,
        "eventType": container["label"],
        "eventSeverity": container["severity"],
    }

    response = call_ciscoumbrella(
        "POST", CISCOUMBRELLA_ENDPOINT_EVENTS, asset, json=[event]
    )
    response_json = response.json()
    soar.set_message(CISCOUMBRELLA_LIST_UPDATED_WITH_GUID.format(id=response_json["id"]))
    return BlockDomainOutput(id=response_json["id"])
