"""Keep firmware login responses compatible while reviewing security findings."""

from unittest.mock import patch
from urllib.parse import parse_qs

import httpx
import pytest

from custom_components.miwifi.enum import EncryptionAlgorithm
from custom_components.miwifi.luci import LuciClient

# Synthetic inputs; expected digests calculated independently with Node crypto.
# The formula and public constant were checked against the router's login page.
NONCE = "0_02:00:00:00:00:01_1700000000_123"
VECTORS = [
    (EncryptionAlgorithm.SHA1, "Synthetic-test-password-42",
     "914cf61ad06c752b2ad0bd1de3c36f2a92c77f0e"),
    (EncryptionAlgorithm.SHA1, "Contraseña-测试-42",
     "53031d345c7cf4fe7c17822f583068adcdfe3c80"),
    (EncryptionAlgorithm.SHA256, "Synthetic-test-password-42",
     "d7ea88edcd6a9404645954565ac75f538f5d7525d398d2238286fee286a4e447"),
    (EncryptionAlgorithm.SHA256, "Contraseña-测试-42",
     "e2594955f69ac38cdb40efe6cddf862f282bdfdf95db2b78b278fa0d85620cdd"),
]


@pytest.mark.parametrize("algorithm,password,expected", VECTORS)
@pytest.mark.asyncio
async def test_login_sends_firmware_challenge_not_plain_password(
    algorithm, password, expected,
) -> None:
    """Exercise the real form POST, including UTF-8 and both firmware modes."""
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"code": 0, "token": "synthetic-token"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        luci = LuciClient(client, "192.0.2.1", password, algorithm, protocol="http")
        with patch.object(luci, "generate_nonce", return_value=NONCE):
            await luci.login()

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert request.url.path.endswith("/api/xqsystem/login")
    form = parse_qs(request.content.decode())
    assert form["password"] == [expected]
    assert form["nonce"] == [NONCE]
    assert password.encode() not in request.content
    assert password not in str(luci.diagnostics)
    assert expected not in str(luci.diagnostics)
    assert luci._token == "synthetic-token"
