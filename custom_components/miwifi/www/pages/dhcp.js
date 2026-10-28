import { html } from "../vendor/lit.js?v=3.13.2";
import "../components/miwifi-dhcp.js?v=3.13.2";

export const renderDhcp = hass => html`<miwifi-dhcp .hass=${hass}></miwifi-dhcp>`;
