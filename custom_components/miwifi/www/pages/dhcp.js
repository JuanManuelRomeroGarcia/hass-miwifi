import { html } from "../vendor/lit.js?v=3.11.0";
import "../components/miwifi-dhcp.js?v=3.11.0";

export const renderDhcp = hass => html`<miwifi-dhcp .hass=${hass}></miwifi-dhcp>`;
