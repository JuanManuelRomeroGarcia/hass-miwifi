import { html } from "../vendor/lit.js?v=3.12.0";
import "../components/miwifi-dhcp.js?v=3.12.0";

export const renderDhcp = hass => html`<miwifi-dhcp .hass=${hass}></miwifi-dhcp>`;
