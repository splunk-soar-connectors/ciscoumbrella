from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.logging import getLogger

from .actions import register_actions
from .actions.test_connectivity import run_test_connectivity
from .asset import Asset

logger = getLogger()


def create_ciscoumbrella_app() -> App:
    app = App(
        name="Cisco Umbrella",
        app_type="endpoint",
        logo="logo_ciscoumbrella.svg",
        logo_dark="logo_ciscoumbrella_dark.svg",
        product_vendor="Cisco",
        product_name="Cisco Umbrella",
        publisher="Splunk",
        appid="96f3e021-5396-42d0-97f4-4fab683e9adb",
        fips_compliant=True,
        asset_cls=Asset,
    )

    @app.test_connectivity()
    def test_connectivity(soar: SOARClient, asset: Asset) -> None:
        run_test_connectivity(soar, asset, app=app)

    return register_actions(app)


app: App = create_ciscoumbrella_app()


if __name__ == "__main__":
    app.cli()
