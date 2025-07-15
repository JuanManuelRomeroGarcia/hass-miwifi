from homeassistant.core import HomeAssistant
from homeassistant.components import websocket_api
from homeassistant.helpers.typing import ConfigType
from .const import DOMAIN

@websocket_api.websocket_command({
    "type": "miwifi/get_download_url",
})
@websocket_api.require_admin
async def handle_get_download_url(hass: HomeAssistant, connection, msg):
    """Return the latest ZIP download URL."""
    url = hass.data.get(DOMAIN, {}).get("last_log_zip_url")

    if url:
        connection.send_result(msg["id"], {"url": url})
    else:
        connection.send_error(msg["id"], "no_file", "No download available yet.")
