import { html } from "../vendor/lit.js?v=3.9.1";
import "../components/miwifi-dhcp.js?v=3.9.1";

export const renderDhcp = hass => html`<miwifi-dhcp .hass=${hass}></miwifi-dhcp>`;
