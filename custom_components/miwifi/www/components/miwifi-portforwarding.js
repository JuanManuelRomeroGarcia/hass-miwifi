import { LitElement, html, css } from "../vendor/lit.js?v=3.7.0";
import { localize } from "../translations/localize.js?v=3.7.0";
import { logToBackend } from "../pages/utils.js?v=3.7.0";


class MiWiFiPortForwarding extends LitElement {
  static properties = {
    hass: {},
    rules1: { state: true },
    rules2: { state: true },
    showModal: { state: true },
    modalType: { state: true },
    form1: { state: true },
    form2: { state: true },
    sensor: { state: true }
  };

  constructor() {
    super();
    this.rules1 = [];
    this.rules2 = [];
    this.showModal = false;
    this.modalType = 1;
    this.form1 = { name: "", ip: "", proto: 1, sport: "", dport: "" };
    this.form2 = { name: "", ip: "", proto: 1, fport: "", tport: "" };
    this.sensor = null;
  }

  updated(changedProps) {
    if ((changedProps.has("hass") || !this.sensor) && this.hass?.states) {
      const s = this.hass.states["sensor.miwifi_nat_rules"];
      if (s && s !== this.sensor) {
        logToBackend(this.hass, "debug", "[MiWiFi] Sensor NAT updated");
        this.sensor = s;
        this.rules1 = s?.attributes?.ftype_1 || [];
        this.rules2 = s?.attributes?.ftype_2 || [];
      } else {
        logToBackend(this.hass, "warning", "[MiWiFi] Sensor NAT not found (willUpdate)");
      }
    }
  }

  firstUpdated() {
    setTimeout(() => {
      if (!this.sensor && this.hass?.states) {
        const s = this.hass.states["sensor.miwifi_nat_rules"];
        if (s) {
          logToBackend(this.hass, "debug", "[MiWiFi] Sensor NAT found (fallback)");
          this.sensor = s;
          this.rules1 = s?.attributes?.ftype_1 || [];
          this.rules2 = s?.attributes?.ftype_2 || [];
        } else {
          logToBackend(this.hass, "warning", "[MiWiFi] Sensor NAT not available (fallback)");
        }
      }
    }, 1000);
  }

  async _addRule() {
    const type = this.modalType;
    const form = type === 1 ? this.form1 : this.form2;
    const data = {
      ip: form.ip,
      name: form.name,
      proto: parseInt(form.proto),
    };
    if (type === 1) {
      data.sport = parseInt(form.sport);
      data.dport = parseInt(form.dport);
    } else {
      data.fport = parseInt(form.fport);
      data.tport = parseInt(form.tport);
    }

    await this.hass.callService("miwifi", type === 1 ? "add_port" : "add_range_port", data);
    await this.hass.callService("miwifi", "refresh_nat_rules");
    setTimeout(() => this._refreshRules(), 1000);
    this._closeModal();
  }

  async _deleteRule(proto, port) {
    const confirmMsg = localize("portforwarding.confirm_delete") || "Are you sure you want to delete this rule?";
    if (!window.confirm(confirmMsg)) return;

    await this.hass.callService("miwifi", "delete_port", { proto, port });
    await this.hass.callService("miwifi", "refresh_nat_rules");
    setTimeout(() => this._refreshRules(), 1000);
  }

  _openModal(type) {
    this.modalType = type;
    this.showModal = true;
  }

  _closeModal() {
    this.showModal = false;
  }

  _refreshRules() {
    const s = this.hass.states["sensor.miwifi_nat_rules"];
    if (s) {
      this.sensor = s;
      this.rules1 = s.attributes.ftype_1 || [];
      this.rules2 = s.attributes.ftype_2 || [];
    } else {
      logToBackend(this.hass, "warning", "[MiWiFi] Could not refresh NAT sensor");
    }
  }

  render() {
    const protoText = (p) => p === 1 ? "TCP" : p === 2 ? "UDP" : "TCP/UDP";
    const f = this.modalType === 1 ? this.form1 : this.form2;

    return html`
      <div class="content">
        ${this.sensor ? html`
          <div class="nat-summary">
            <b>📊 Reglas NAT:</b><br />
            ${localize("state_attributes.total") || "Total"}: ${this.sensor.attributes.total || 0} |
            ${localize("state_attributes.ftype_1") || "Individuals"}: ${this.sensor.attributes.ftype_1?.length || 0} |
            ${localize("state_attributes.ftype_2") || "By range"}: ${this.sensor.attributes.ftype_2?.length || 0}<br />
            ${localize("state_attributes.source") || "Source"}: ${this.sensor.attributes.source || "-"}
          </div>
        ` : ""}
        <h2>${localize("panel.portforwarding_title") || "Port Forwarding"}</h2>

        <div class="section-title">📦 ${localize("portforwarding.individual_title") || "Individual Rules"}
          <button class="miwifi-button small" @click=${() => this._openModal(1)}>${localize("portforwarding.add_rule_button") || "Add Rule"}</button>
        </div>

        <table class="rules-table">
        <thead>
          <tr>
            <th>${localize("portforwarding.column_name")}</th>
            <th>${localize("portforwarding.column_proto")}</th>
            <th>${localize("portforwarding.external_port") || "External Port"}</th>
            <th>${localize("portforwarding.column_target_ip") || "Target IP"}</th>
            <th>${localize("portforwarding.internal_port") || "Internal Port"}</th>
            <th>${localize("portforwarding.column_actions")}</th>
          </tr>
        </thead>
        <tbody>
          ${this.rules1.map(rule => html`
            <tr>
              <td data-label="${localize('portforwarding.column_name')}">${rule.name}</td>
              <td data-label="${localize('portforwarding.column_proto')}">${protoText(rule.proto)}</td>
              <td data-label="${localize('portforwarding.external_port')}">${rule.srcport}</td>
              <td data-label="${localize('portforwarding.column_target_ip')}">${rule.destip}</td>
              <td data-label="${localize('portforwarding.internal_port')}">${rule.destport}</td>
              <td data-label="${localize('portforwarding.column_actions')}">
                <button @click=${() => this._deleteRule(rule.proto, rule.srcport)}>
                  ${localize("portforwarding.delete_button")}
                </button>
              </td>
            </tr>
          `)}
        </tbody>
      </table>


        <div class="section-title">📦 ${localize("portforwarding.range_title") || "Range Rules"}
          <button class="miwifi-button small" @click=${() => this._openModal(2)}>${localize("portforwarding.add_rule_button") || "Add Rule"}</button>
        </div>

        <table class="rules-table">
        <thead>
          <tr>
            <th>${localize("portforwarding.column_name")}</th>
            <th>${localize("portforwarding.column_proto")}</th>
            <th>${localize("portforwarding.range_start_port")}</th>
            <th>${localize("portforwarding.range_end_port")}</th>
            <th>${localize("portforwarding.column_target_ip")}</th>
            <th>${localize("portforwarding.column_actions")}</th>
          </tr>
        </thead>
        <tbody>
          ${this.rules2.map(rule => html`
            <tr>
              <td data-label="${localize('portforwarding.column_name')}">${rule.name}</td>
              <td data-label="${localize('portforwarding.column_proto')}">${protoText(rule.proto)}</td>
              <td data-label="${localize('portforwarding.range_start_port')}">${rule.srcport.f}</td>
              <td data-label="${localize('portforwarding.range_end_port')}">${rule.srcport.t}</td>
              <td data-label="${localize('portforwarding.column_target_ip')}">${rule.destip}</td>
              <td data-label="${localize('portforwarding.column_actions')}">
                <button @click=${() => this._deleteRule(rule.proto, rule.srcport.f)}>
                  ${localize("portforwarding.delete_button")}
                </button>
              </td>
            </tr>
          `)}
        </tbody>
      </table>


        ${this.showModal ? html`
          <div class="overlay" @click=${this._closeModal}></div>
          <div class="modal">
            <h3>${this.modalType === 1 ? localize("portforwarding.create_individual") : localize("portforwarding.create_range")}</h3>
            <div class="modal-form">
              <input placeholder="${localize("portforwarding.column_name")}" .value=${f.name} @input=${e => f.name = e.target.value} />
              <select @change=${e => f.proto = parseInt(e.target.value)}>
                <option value="1" ?selected=${f.proto === 1}>TCP</option>
                <option value="2" ?selected=${f.proto === 2}>UDP</option>
                <option value="3" ?selected=${f.proto === 3}>TCP/UDP</option>
              </select>
              ${this.modalType === 1 ? html`
                <input placeholder="${localize("portforwarding.external_port")}" .value=${f.sport} @input=${e => f.sport = e.target.value} />
                <input placeholder="${localize("portforwarding.internal_port")}" .value=${f.dport} @input=${e => f.dport = e.target.value} />
              ` : html`
                <input placeholder="${localize("portforwarding.range_start_port")}" .value=${f.fport} @input=${e => f.fport = e.target.value} />
                <input placeholder="${localize("portforwarding.range_end_port")}" .value=${f.tport} @input=${e => f.tport = e.target.value} />
              `}
              <input placeholder="${localize("portforwarding.target_ip")}" .value=${f.ip} @input=${e => f.ip = e.target.value} />
              <button class="miwifi-button" @click=${() => this._addRule()}>${localize("portforwarding.confirm_add")}</button>
            </div>
          </div>
        ` : ""}
      </div>
    `;
  }

  static styles = css`
    .content {
        text-align: center;
        color: white;
        padding: 1rem;
    }

    h2 {
        font-size: 24px;
        margin-bottom: 1rem;
    }

    .section-title {
        font-size: 18px;
        font-weight: bold;
        color: white;
        margin-top: 32px;
        margin-bottom: 12px;
        text-align: center;
    }

    .rules-table {
        width: 100%;
        max-width: 880px;
        margin: auto;
        margin-bottom: 24px;
        background: #fefefe;
        color: #333;
        border-radius: 10px;
        border: 1px solid #ccc;
        overflow: hidden;
        box-shadow: 0px 4px 8px rgba(0,0,0,0.15);
    }

    .rules-table th {
        background: #1a73e8;
        color: white;
        padding: 10px;
        font-weight: bold;
        font-size: 14px;
    }

    .rules-table td {
        padding: 10px;
        border-bottom: 1px solid #e0e0e0;
        font-size: 14px;
    }

    .rules-table tr:last-child td {
        border-bottom: none;
    }

    .miwifi-button.small {
        font-size: 13px;
        margin-left: 12px;
        padding: 6px 14px;
        border: none;
        border-radius: 8px;
        background: #0b5ed7;
        color: white;
        cursor: pointer;
        transition: background 0.2s ease;
    }

    .miwifi-button.small:hover {
        background: #0848b4;
    }

    .overlay {
        position: fixed;
        top: 0; left: 0;
        width: 100vw; height: 100vh;
        background: rgba(0, 0, 0, 0.5);
        z-index: 999;
    }

    .modal {
        position: fixed;
        top: 50%; left: 50%;
        transform: translate(-50%, -50%);
        background: white;
        color: black;
        padding: 20px;
        border-radius: 12px;
        z-index: 1000;
        width: 320px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        animation: fadeIn 0.3s ease;
    }

    .modal-form input, .modal-form select {
        display: block;
        width: 100%;
        margin-bottom: 12px;
        padding: 10px;
        border: 1px solid #ccc;
        border-radius: 6px;
        font-size: 14px;
    }

    .modal-form button {
        width: 100%;
        padding: 10px;
        background: #1a73e8;
        color: white;
        font-weight: bold;
        border: none;
        border-radius: 8px;
        cursor: pointer;
    }

    .modal-form button:hover {
        background: #0c57c2;
    }
    
    button.reboot-btn {
        background: #f44336;
        color: white;
        font-weight: bold;
        border: none;
        border-radius: 10px;
        padding: 12px 20px;
        cursor: pointer;
        width: 100%;
        margin-top: 16px;
    }

    button.reboot-btn:hover {
        background: #e53935;
    }

    .nat-summary {
        background: #fff3cd;
        color: #856404;
        border: 1px solid #ffeeba;
        border-radius: 10px;
        padding: 14px;
        margin: 16px auto 24px;
        font-size: 15px;
        max-width: 880px;
        box-shadow: 0 0 6px rgba(0,0,0,0.1);
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: scale(0.95); }
        to { opacity: 1; transform: scale(1); }
    }


    .rules-table {
        width: 100%;
        max-width: 880px;
        margin: auto;
        margin-bottom: 24px;
        background: #fefefe;
        color: #333;
        border-radius: 10px;
        border: 1px solid #ccc;
        overflow: hidden;
        box-shadow: 0px 4px 8px rgba(0,0,0,0.15);
    }

    .rules-table th {
        background: #1a73e8;
        color: white;
        padding: 10px;
        font-weight: bold;
        font-size: 14px;
    }

    .rules-table td {
        padding: 10px;
        border-bottom: 1px solid #e0e0e0;
        font-size: 14px;
    }

    .rules-table tr:last-child td {
        border-bottom: none;
    }

    @media (max-width: 768px) {
      .rules-table,
      .rules-table thead,
      .rules-table tbody,
      .rules-table th,
      .rules-table td,
      .rules-table tr {
        display: block;
      }

      .rules-table thead {
        display: none;
      }

      .rules-table tr {
        margin-bottom: 16px;
        background: #1a73e8;
        border-radius: 10px;
        padding: 10px;
        box-shadow: 0px 4px 8px rgba(0,0,0,0.2);
      }

      .rules-table td {
        padding: 8px 12px;
        font-size: 14px;
        color: white;
        position: relative;
        text-align: left;
      }

      .rules-table td::before {
        content: attr(data-label);
        font-weight: bold;
        display: block;
        color: #ccc;
        margin-bottom: 4px;
      }

      .modal {
        position: fixed;
        top: 50%; left: 50%;
        transform: translate(-50%, -50%);
        background: white;
        color: black;
        padding: 20px;
        border-radius: 12px;
        z-index: 1000;
        width: 80%;
        box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        animation: fadeIn 0.3s ease;
      }

      .modal-form input, .modal-form select {
          display: block;
          width: 90%;
          margin-bottom: 12px;
          padding: 10px;
          border: 1px solid #ccc;
          border-radius: 6px;
          font-size: 14px;
      }
  `;
}

customElements.define("miwifi-portforwarding", MiWiFiPortForwarding);