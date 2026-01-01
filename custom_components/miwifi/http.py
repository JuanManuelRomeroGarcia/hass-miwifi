from __future__ import annotations

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from .const import DOMAIN


class MiWifiAddUnsupportedPage(HomeAssistantView):
    """Small HTML page that calls the HA service using the frontend token."""

    # IMPORTANTE:
    # - NO usar /miwifi/... porque colisiona con el panel (ruta SPA).
    # - Usar /api/... evita que el panel capture la URL.
    url = f"/api/{DOMAIN}/add_unsupported"
    name = f"api:{DOMAIN}_add_unsupported_page"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        feature = (request.query.get("feature") or "").strip()
        model = (request.query.get("model") or "").strip()

        html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>MiWiFi - add_unsupported</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="font-family:sans-serif;padding:16px;">
  <h2>MiWiFi</h2>
  <p id="status">Procesando…</p>
  <pre id="details" style="white-space:pre-wrap;"></pre>

<script>
(() => {{
  const feature = {feature!r};
  const model = {model!r};

  const statusEl = document.getElementById("status");
  const detailsEl = document.getElementById("details");

  function parseTokens(raw) {{
    if (!raw) return null;
    try {{
      const obj = JSON.parse(raw);

      // Formato típico:
      // {{ access_token, refresh_token, expires }}
      if (obj && obj.access_token) {{
        return {{
          access_token: obj.access_token,
          refresh_token: obj.refresh_token || null
        }};
      }}

      // Fallbacks defensivos por si HA cambia estructura:
      const candidates = [
        obj?.data,
        obj?.value,
        obj?.tokens,
        obj?.token
      ];
      for (const c of candidates) {{
        if (c && c.access_token) {{
          return {{
            access_token: c.access_token,
            refresh_token: c.refresh_token || null
          }};
        }}
      }}
    }} catch (e) {{}}
    return null;
  }}

  function getTokensFromLocalStorage() {{
    const directKeys = ["hassTokens", "hassTokens_v2"];

    for (const k of directKeys) {{
      const tok = parseTokens(localStorage.getItem(k));
      if (tok && tok.access_token) return tok;
    }}

    // fallback: cualquier key que contenga hasstokens
    for (let i = 0; i < localStorage.length; i++) {{
      const k = localStorage.key(i);
      if (!k || !k.toLowerCase().includes("hasstokens")) continue;
      const tok = parseTokens(localStorage.getItem(k));
      if (tok && tok.access_token) return tok;
    }}

    return null;
  }}

  async function refreshAccessToken(refreshToken) {{
    // Endpoint estándar de HA para refrescar tokens
    // grant_type=refresh_token
    const body = new URLSearchParams();
    body.set("grant_type", "refresh_token");
    body.set("refresh_token", refreshToken);
    body.set("client_id", window.location.origin + "/");

    const resp = await fetch("/auth/token", {{
      method: "POST",
      headers: {{
        "Content-Type": "application/x-www-form-urlencoded"
      }},
      body: body.toString()
    }});

    if (!resp.ok) {{
      const t = await resp.text();
      throw new Error("refresh_token failed: HTTP " + resp.status + " - " + t);
    }}

    return await resp.json(); // {{ access_token, expires_in, ... }}
  }}

  async function postAddUnsupported(accessToken) {{
    const resp = await fetch("/api/services/{DOMAIN}/add_unsupported", {{
      method: "POST",
      headers: {{
        "Authorization": "Bearer " + accessToken,
        "Content-Type": "application/json"
      }},
      body: JSON.stringify({{ feature, model }})
    }});

    const text = await resp.text();
    return {{ ok: resp.ok, status: resp.status, text }};
  }}

  async function run() {{
    if (!feature || !model) {{
      statusEl.textContent = "Faltan parámetros: feature/model.";
      detailsEl.textContent = "feature=" + feature + " model=" + model;
      return;
    }}

    const tokens = getTokensFromLocalStorage();
    if (!tokens?.access_token) {{
      statusEl.textContent =
        "No se encontró token del frontend. Abre este link desde el mismo dominio y con sesión iniciada en Home Assistant.";
      detailsEl.textContent = "feature=" + feature + "\\nmodel=" + model;
      return;
    }}

    // 1) Intento normal con access_token
        try {{
        let r = await postAddUnsupported(tokens.access_token);
        if (r.ok) {{
    statusEl.textContent = "OK: añadido (o ya existía). Volviendo a Home Assistant…";
    detailsEl.textContent = r.text || "";

    setTimeout(() => {{
        // si se abrió como popup/tab, intenta cerrar
        try {{ if (window.opener) window.close(); }} catch (e) {{}}

        // si no se puede cerrar, vuelve a la pantalla anterior
        if (window.history.length > 1) {{
        window.history.back();
        }} else {{
        window.location.href = "/";
        }}
    }}, 600);

    return;
    }}


      // 2) Si da 401, intentar refrescar y reintentar
      if (r.status === 401 && tokens.refresh_token) {{
        statusEl.textContent = "Token expirado. Refrescando…";
        const refreshed = await refreshAccessToken(tokens.refresh_token);
        const newAccess = refreshed.access_token;

        r = await postAddUnsupported(newAccess);
        if (r.ok) {{
            statusEl.textContent = "OK (tras refresh): añadido (o ya existía). Volviendo…";
            detailsEl.textContent = r.text || "";

            setTimeout(() => {{
                try {{ if (window.opener) window.close(); }} catch (e) {{}}
                if (window.history.length > 1) {{
                window.history.back();
                }} else {{
                window.location.href = "/";
                }}
            }}, 600);

            return;
            }}


        statusEl.textContent = "Error tras refresh: HTTP " + r.status;
        detailsEl.textContent = r.text || "";
        return;
      }}

      statusEl.textContent = "Error: HTTP " + r.status;
      detailsEl.textContent = r.text || "";
    }} catch (e) {{
      statusEl.textContent = "Excepción llamando al servicio.";
      detailsEl.textContent = String(e);
    }}
  }}

  run();
}})();
</script>
</body>
</html>
"""
        return web.Response(text=html, content_type="text/html")


async def async_register_http_views(hass) -> None:
    data = hass.data.setdefault(DOMAIN, {})
    if data.get("_http_views_registered"):
        return

    hass.http.register_view(MiWifiAddUnsupportedPage)
    data["_http_views_registered"] = True
