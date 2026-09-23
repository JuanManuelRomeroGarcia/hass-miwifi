"""Authenticated downloads for MiWiFi diagnostic exports."""

from __future__ import annotations

import re
from pathlib import Path

from aiohttp import web
from homeassistant.components.http import KEY_HASS, HomeAssistantView

from .const import DOMAIN


_EXPORT_NAME = re.compile(r"(?:logs|dump)_[A-Za-z0-9_-]+\.zip\Z")
_LEGACY_EXPORT_NAME = re.compile(r"(?:logs|dump)_[A-Za-z0-9_-]+\.(?:zip|json)\Z")


class MiWifiExportView(HomeAssistantView):
    """Serve private exports only to an authenticated administrator."""

    url = f"/api/{DOMAIN}/exports/{{filename}}"
    name = f"api:{DOMAIN}_export"
    requires_auth = True

    async def get(self, request: web.Request, filename: str) -> web.StreamResponse:
        user = request.get("hass_user")
        if user is None or not user.is_admin:
            raise web.HTTPForbidden()
        if not _EXPORT_NAME.fullmatch(filename):
            raise web.HTTPNotFound()

        path = Path(request.app[KEY_HASS].config.path(DOMAIN, "exports", filename))
        if not path.is_file():
            raise web.HTTPNotFound()

        return web.FileResponse(
            path,
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )


def _remove_legacy_public_exports(directory: Path) -> None:
    """Remove files previous releases made available without authentication."""

    if not directory.is_dir():
        return
    for path in directory.iterdir():
        if _LEGACY_EXPORT_NAME.fullmatch(path.name) and path.is_file():
            path.unlink()


async def async_register_http_views(hass) -> None:
    data = hass.data.setdefault(DOMAIN, {})
    if data.get("_http_views_registered"):
        return

    await hass.async_add_executor_job(
        _remove_legacy_public_exports,
        Path(hass.config.path("www", DOMAIN, "exports")),
    )
    hass.http.register_view(MiWifiExportView)
    data["_http_views_registered"] = True
