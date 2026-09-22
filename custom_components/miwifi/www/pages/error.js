import { html } from "../vendor/lit.js?v=3.7.0";
import { localize } from "../translations/localize.js?v=3.7.0";

export function renderError(hass) {
  return html`
    <div class="content text-center">
      <h2>${localize("error_title")}</h2>
      <p>${localize("error_not_found")}</p>
      <p>${localize("error_suggestion")}</p>
    </div>
  `;
}
