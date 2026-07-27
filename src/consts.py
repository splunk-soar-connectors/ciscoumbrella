CISCOUMBRELLA_API_BASE_URL = "https://s-platform.api.opendns.com/1.0"

CISCOUMBRELLA_CONFIG_PARAMS_REQUIRED = (
    "Please provide the Customer key in the asset configuration"
)
CISCOUMBRELLA_TEST_CONNECTIVITY_PASSED_MSG = "Test Connectivity Passed"
CISCOUMBRELLA_TEST_CONNECTIVITY_FAILED_MSG = "Test Connectivity Failed"
CISCOUMBRELLA_MSG_GET_DOMAIN_LIST_TEST = (
    "Querying a single domain entry to check credentials"
)
CISCOUMBRELLA_USING_BASE_URL = "Using url: {base_url}"
CISCOUMBRELLA_CONNECTING_TO_MSG = "Connecting to {host}..."

CISCOUMBRELLA_ERR_SERVER_CONNECTION = "Connection failed"
CISCOUMBRELLA_ERR_FROM_SERVER = "API failed, Status code: {status}, Message: {message}"
CISCOUMBRELLA_ERR_INVALID_JSON = "Response is not a valid json"

CISCOUMBRELLA_ENDPOINT_DOMAINS = "/domains"
CISCOUMBRELLA_ENDPOINT_EVENTS = "/events"

CISCOUMBRELLA_JSON_TOTAL_DOMAINS = "total_domains"
CISCOUMBRELLA_LIST_UPDATED_WITH_GUID = "REST API returned success with id: {id}"
CISCOUMBRELLA_UNBLOCK_SUCCESS_MSG = "Domain successfully unblocked"

CISCOUMBRELLA_ERR_GET_CONTAINER_INFO = "Unable to get container information"
CISCOUMBRELLA_EVENT_PROTOCOL_VERSION = "1.0a"
CISCOUMBRELLA_EVENT_PROVIDER_NAME = "Security Platform"

CISCOUMBRELLA_DEFAULT_DOMAIN_LIMIT = 200
CISCOUMBRELLA_DEFAULT_MAX_PAGES = 1000
CISCOUMBRELLA_PAGINATION_EXCEEDED_MSG = (
    "Pagination exceeded the maximum of {max_pages} pages"
)

CISCOUMBRELLA_VALID_INT_MSG = "Please provide a valid integer value in the {param} parameter"
CISCOUMBRELLA_NON_NEG_NON_ZERO_INT_MSG = (
    "Please provide a valid non-zero positive integer value in the {param} parameter"
)
CISCOUMBRELLA_NON_NEG_INT_MSG = (
    "Please provide a valid non-negative integer value in the {param} parameter"
)

DEFAULT_TIMEOUT = 60
