"""Security regression checks for private MiWiFi downloads without a HA runtime."""

from __future__ import annotations

import ast
import datetime
import os
import re
import secrets
import tempfile
import unittest
import zipfile
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock


COMPONENT = Path(__file__).resolve().parents[1] / "custom_components" / "miwifi"


class Forbidden(Exception):
    pass


class NotFound(Exception):
    pass


def _file_response(path, headers):
    return SimpleNamespace(path=path, headers=headers)


def _load_http_code():
    """Execute the actual view and cleanup code with small Home Assistant doubles."""

    tree = ast.parse((COMPONENT / "http.py").read_text(encoding="utf-8"))
    names = {"_EXPORT_NAME", "_LEGACY_EXPORT_NAME"}
    code = [
        node
        for node in tree.body
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id in names for target in node.targets)
        )
        or isinstance(node, (ast.ClassDef, ast.AsyncFunctionDef, ast.FunctionDef))
    ]
    namespace = {
        "re": re,
        "Path": Path,
        "DOMAIN": "miwifi",
        "KEY_HASS": "hass",
        "HomeAssistantView": type("HomeAssistantView", (), {}),
        "web": SimpleNamespace(HTTPForbidden=Forbidden, HTTPNotFound=NotFound, FileResponse=_file_response),
    }
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[future, *code], type_ignores=[])), "http.py", "exec"), namespace)
    return namespace


def _load_log_export_service(notifications):
    tree = ast.parse((COMPONENT / "services.py").read_text(encoding="utf-8"))
    node = next(
        item for item in tree.body
        if isinstance(item, ast.ClassDef) and item.name == "MiWifiDownloadLogsService"
    )
    node.body = [
        item for item in node.body
        if not (
            isinstance(item, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "schema" for target in item.targets)
        )
    ]

    class Notifier:
        def __init__(self, hass):
            pass

        async def get_translations(self):
            return {"title": "MiWiFi"}

        async def notify(self, message, **kwargs):
            notifications.append(message)

    namespace = {
        "os": os,
        "datetime": datetime,
        "secrets": secrets,
        "zipfile": zipfile,
        "partial": partial,
        "DOMAIN": "miwifi",
        "MiWiFiNotifier": Notifier,
        "_LOGGER": Mock(),
    }
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[future, node], type_ignores=[])), "services.py", "exec"), namespace)
    return namespace["MiWifiDownloadLogsService"]


class ExportSecurityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.source = _load_http_code()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.filename = "dump_2026-09-23_01-02-03_1234567890abcdef.zip"
        self.private = self.root / "miwifi" / "exports" / self.filename
        self.private.parent.mkdir(parents=True)
        self.private.write_bytes(b"test archive")

        config = SimpleNamespace(path=lambda *parts: str(self.root.joinpath(*parts)))
        self.hass = SimpleNamespace(config=config, data={}, http=SimpleNamespace(register_view=Mock()))

        async def executor(func, *args):
            return func(*args)

        self.hass.async_add_executor_job = executor

    def _request(self, *, admin):
        request = {"hass_user": SimpleNamespace(is_admin=admin)}
        return SimpleNamespace(get=request.get, app={"hass": self.hass})

    async def test_download_requires_admin_and_private_file(self):
        view = self.source["MiWifiExportView"]()
        self.assertTrue(view.requires_auth)
        with self.assertRaises(Forbidden):
            await view.get(self._request(admin=False), self.filename)

        response = await view.get(self._request(admin=True), self.filename)
        self.assertEqual(response.path, self.private)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    async def test_traversal_and_missing_files_are_rejected(self):
        view = self.source["MiWifiExportView"]()
        with self.assertRaises(NotFound):
            await view.get(self._request(admin=True), "../secrets.zip")
        with self.assertRaises(NotFound):
            await view.get(self._request(admin=True), "logs_missing.zip")

    async def test_old_public_exports_are_removed_before_registration(self):
        public = self.root / "www" / "miwifi" / "exports"
        public.mkdir(parents=True)
        for name in ("logs_20260923-080000.zip", "dump_2026-09-23_08-00-00.zip", "dump_2026-09-23_08-00-00.json"):
            (public / name).write_text("private network data")
        unrelated = public / "readme.txt"
        unrelated.write_text("keep")

        await self.source["async_register_http_views"](self.hass)

        self.assertEqual(list(public.iterdir()), [unrelated])
        self.hass.http.register_view.assert_called_once_with(self.source["MiWifiExportView"])

    async def test_log_service_creates_only_private_archive(self):
        logs = self.root / "miwifi" / "logs"
        logs.mkdir(parents=True)
        (logs / "miwifi_info.log").write_text("router event")
        notifications = []
        service_class = _load_log_export_service(notifications)
        self.hass.config.config_dir = str(self.root)

        await service_class(self.hass).async_call_service(None)

        archives = list((self.root / "miwifi" / "exports").glob("logs_*.zip"))
        self.assertEqual(len(archives), 1)
        with zipfile.ZipFile(archives[0]) as archive:
            self.assertEqual(archive.read("miwifi_info.log"), b"router event")
        self.assertFalse((self.root / "www").exists())
        self.assertTrue(self.hass.data["miwifi"]["last_log_zip_url"].startswith("/api/miwifi/exports/"))
        self.assertTrue(notifications)


if __name__ == "__main__":
    unittest.main()
