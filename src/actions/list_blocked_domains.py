from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..client import validate_integer
from ._helpers import _paginate_domains


class ListBlockedDomainsParams(Params):
    limit: float | None = Param(
        description="Maximum number of results to fetch", default=200
    )


class ListBlockedDomainsOutput(ActionOutput):
    name: str = OutputField(
        cef_types=["domain"], example_values=["test.com"], column_name="Domain"
    )
    id: float = OutputField(
        cef_types=["cisco domain id"],
        example_values=[25837],
        column_name="Domain ID",
    )
    lastSeenAt: float = OutputField(example_values=[1662618587])


class ListBlockedDomainsSummary(ActionOutput):
    total_domains: int = OutputField(example_values=[10])


def list_blocked_domains(
    params: ListBlockedDomainsParams, soar: SOARClient, asset: Asset
) -> list[ListBlockedDomainsOutput]:
    domain_limit = validate_integer(params.limit, "'limit'")
    domain_list = _paginate_domains(asset, limit=domain_limit)
    output = [ListBlockedDomainsOutput(**domain) for domain in domain_list]
    soar.set_summary(ListBlockedDomainsSummary(total_domains=len(output)))
    return output
