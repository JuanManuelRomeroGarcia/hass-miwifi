import { html } from "../vendor/lit.js?v=3.13.3";
import "../components/miwifi-dhcp.js?v=3.13.3";

export const renderDhcp = hass => html`<miwifi-dhcp .hass=${hass}></miwifi-dhcp>`;
