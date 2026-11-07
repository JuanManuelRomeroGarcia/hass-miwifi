import { html } from "../vendor/lit.js?v=__MIWIFI_VERSION__";
import { localize } from "../translations/localize.js?v=__MIWIFI_VERSION__";

export function renderError(hass) {
  return html`
    <div class="content text-center">
      <h2>${localize("error_title")}</h2>
      <p>${localize("error_not_found")}</p>
      <p>${localize("error_suggestion")}</p>
    </div>
  `;
}
