from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..client import call_ciscoumbrella
from ..consts import CISCOUMBRELLA_ENDPOINT_DOMAINS, CISCOUMBRELLA_UNBLOCK_SUCCESS_MSG


class UnblockDomainParams(Params):
    domain: str = Param(
        description="Domain to unblock",
        primary=True,
        cef_types=["domain"],
        column_name="Domain",
    )


class UnblockDomainOutput(ActionOutput):
    pass


def unblock_domain(
    params: UnblockDomainParams, soar: SOARClient, asset: Asset
) -> UnblockDomainOutput:
    call_ciscoumbrella(
        "DELETE",
        CISCOUMBRELLA_ENDPOINT_DOMAINS,
        asset,
        params={"where[name]": params.domain},
    )
    soar.set_message(CISCOUMBRELLA_UNBLOCK_SUCCESS_MSG)
    return UnblockDomainOutput()
