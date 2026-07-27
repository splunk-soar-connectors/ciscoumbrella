"""One-off: install the app via the SDK's exact /app_install flow, but with an
extended httpx timeout (the SDK hardcodes 30s write, too short for a ~95s upload
on this slow link). Reuses phantom_install_app verbatim; only the client timeout
differs from soar_sdk/cli/package/utils.phantom_get_login_session.
"""

import asyncio
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from soar_sdk.cli.package.utils import phantom_install_app


@asynccontextmanager
async def login_session_extended_timeout(base_url, username, password):
    timeout = httpx.Timeout(180.0, read=180.0)  # only change vs SDK's 30/60
    async with httpx.AsyncClient(
        base_url=base_url,
        verify=False,  # noqa: S501 -- matches SDK
        timeout=timeout,
        auth=(username, password),
    ) as client:
        response = await client.get("/", follow_redirects=True)
        response.raise_for_status()
        csrf_token = response.cookies.get("csrftoken")
        if not csrf_token:
            raise RuntimeError("Could not obtain CSRF token from SOAR instance")
        client.cookies.update(response.cookies)
        yield client


async def main():
    tgz = Path(sys.argv[1]).resolve()
    instance = sys.argv[2]
    username = sys.argv[3]
    password = os.environ["PHANTOM_PASSWORD"]
    force = True

    base_url = instance if instance.startswith("https://") else f"https://{instance}"
    payload = {"app": tgz.read_bytes()}

    async with login_session_extended_timeout(base_url, username, password) as client:
        response = await phantom_install_app(client, "app_install", payload, force)

    print(f"HTTP {response.status_code}")
    body = response.text
    print(body[:2000])
    response.raise_for_status()
    print("INSTALL_OK")


if __name__ == "__main__":
    asyncio.run(main())
