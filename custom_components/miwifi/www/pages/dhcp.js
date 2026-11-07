import { html } from "../vendor/lit.js?v=__MIWIFI_VERSION__";
import "../components/miwifi-dhcp.js?v=__MIWIFI_VERSION__";

export const renderDhcp = hass => html`<miwifi-dhcp .hass=${hass}></miwifi-dhcp>`;
