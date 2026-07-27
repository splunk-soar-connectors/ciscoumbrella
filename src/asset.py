from soar_sdk.asset import AssetField, BaseAsset


class Asset(BaseAsset):
    customer_key: str = AssetField(description="Cisco Customer key", sensitive=True)
    retry_count: float | None = AssetField(
        description="Maximum attempts to retry the API call (Default: 3)", default=3.0
    )
    retry_wait_time: float | None = AssetField(
        description="Delay in seconds between retries (Default: 60)", default=60.0
    )
