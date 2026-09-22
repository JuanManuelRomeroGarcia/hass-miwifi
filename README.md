# MiWiFi for Home Assistant
[![HACS](https://img.shields.io/badge/HACS-Custom-41BDF5.svg?style=for-the-badge)](https://github.com/hacs/integration)
[![Validation](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/actions/workflows/validate.yml/badge.svg)](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/actions/workflows/validate.yml)
[![Telegram](https://img.shields.io/badge/Telegram-channel-34ABDF.svg?style=for-the-badge)](https://t.me/XiaohackRouters)

The component allows you to monitor devices and manage routers based on [MiWiFi](http://miwifi.com/) from [Home Assistant](https://www.home-assistant.io/).

❗ Supports routers with original or original patched MiWifi firmware

❗ On the modified firmware, not all functionality may work

## More info
- [Install](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Install)
- [Config](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Config)
  - [Advanced config](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Config#advanced-config)
    - [Automatically remove devices](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Config#automatically-remove-devices)
- [Supported routers](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Supported-routers)
  - [Check list](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Supported-routers#check-list)
    - [Required](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Supported-routers#required)
    - [Additional](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Supported-routers#additional)
    - [Action](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Supported-routers#action)
  - [Summary](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Supported-routers#summary)
- [Conflicts](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Conflicts)
- [Entities](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Entities)
- [Services](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Services)
  - [Calculate passwd](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Services#calculate-passwd)
  - [Send request](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Services#send-request)
- [Events](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Events)
  - [Luci response](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Events#luci-response)
- [Performance table](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Performance-table)
- [Example automation](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Example-automation)
  - [Device blocking](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Example-automation#device-blocking)
  - [Lighting automation](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Example-automation#lighting-automation)
- [Diagnostics](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/Diagnostics)
- [FAQ](https://github.com/JuanManuelRomeroGarcia/hass-miwifi/wiki/FAQ)

## Supported routers

Many more Xiaomi and Redmi routers supported by MiWiFi

### Check list

##### Required
- `xqsystem/login` - Authorization;
- `xqsystem/init_info` - Basic information about the router;
- `misystem/status` - Basic information about the router. Diagnostic data, memory, temperature, etc;
- `xqnetwork/mode` - Operating mode. Repeater, Access Point, Mesh, etc.
- `xqnetwork/get_netmode` - Operating mode. Repeater, Access Point, Mesh, etc.

##### Additional
- `misystem/topo_graph` - Topography, auto discovery does not work without it;
- `xqsystem/check_rom_update` - Getting information about a firmware update;
- `xqnetwork/wan_info` - WAN port information;
- `xqsystem/vpn_status` - Information about vpn connection;
- `misystem/led` - Interaction with LEDs;
- `xqnetwork/wifi_detail_all` - Getting information about WiFi adapters;
- `xqnetwork/wifi_diag_detail_all` - Getting information about guest WiFi;
- `xqnetwork/avaliable_channels` - Gets available channels for WiFi adapter;
- `xqnetwork/wifi_connect_devices` - Get information about connected devices;
- `misystem/devicelist` - More information about connected devices;
- `xqnetwork/wifiap_signal` - AP signal in repeater mode;
- `misystem/newstatus` - Additional information about connected devices for force load mode.

##### Action
- `xqsystem/reboot` - Reboot;
- `xqsystem/upgrade_rom` - Firmware update;
- `xqsystem/flash_permission` - Clear permission. Required only for firmware updates;
- `xqnetwork/set_wifi` - Update WiFi settings. Causes the adapter to reboot;
- `xqnetwork/set_wifi_without_restart` - Update Guest WiFi settings.

❗ If your router is not listed or not tested, try adding an integration, it will check everything and give a link to create an issue. You just have to click `Submit new issue`

❗ If at the time of adding the integration only `Router {ip} not supported` message is displayed, please create an issue with the message that the router is not supported, indicating the model of the router.

### Summary

- 🟢 - Supported
- 🔴 - Not supported
- ⚪ - Not tested

| Image                  | Router                                |  Code  |      Required       |             Additional              |         Action          |
|------------------------|---------------------------------------|:------:|:-------------------:|:-----------------------------------:|:-----------------------:|
| ![](images/CB0401.png) | **Xiaomi 5G CPE Pro**                 | CB0401  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R4AV2.png)  | **Mi Router 4A Gigabit V2**           | R4AV2  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RB08.png)   | **Xiaomi Home WiFi**                  |  RB08  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RB06.png)   | **Redmi Router AX6000**               |  RB06  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RA74.png)   | **Redmi Router AX5400**               |  RA74  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RB04.png)   | **Redmi Gaming Router AX5400**        |  RB04  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢⚪🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢⚪🟢🟢🟢</sub>   |
| ![](images/RB02.png)   | **Xiaomi Router AC1200**              |  RB02  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/CR8808.png) | **Xiaomi Router CR8808**              | CR8808 | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RA82.png)   | **Xiaomi Mesh System AX3000**         |  RA82  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RB01.png)   | **Xiaomi Router AX3200**              |  RB01  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RA71.png)   | **Redmi Router AX1800**               |  RA71  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RB03.png)   | **Redmi Router AX6S**                 |  RB03  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RA80.png)   | **Xiaomi Router AX3000**              |  RA80  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RA81.png)   | **Redmi Router AX3000**               |  RA81  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/CR6606.png) | **Xiaomi China Unicom WiFi 6 Router** | CR6606 | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RA70.png)   | **Xiaomi Router AX9000**              |  RA70  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RA50.png)   | **Redmi Router AX5**                  |  RA50  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RA72.png)   | **Xiaomi Router AX6000**              |  RA72  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RA69.png)   | **Redmi Router AX6**                  |  RA69  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R1350.png)  | **Mi Router 4 Pro**                   | R1350  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R2350.png)  | **Mi AIoT Router AC2350**             | R2350  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RA67.png)   | **Redmi Router AX5**                  |  RA67  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RM1800.png) | **Mi Router AX1800**                  | RM1800 | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R3600.png)  | **Xiaomi AIoT Router AX3600**         | R3600  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RM2100.png) | **Redmi Router AC2100**               | RM2100 | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R2100.png)  | **Mi Router AC2100**                  | R2100  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/D01.png)    | **Mi Router Mesh**                    |  D01   | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R4AC.png)   | **Mi Router 4A**                      |  R4AC  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R4A.png)    | **Mi Router 4A Gigabit**              |  R4A   | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R4CM.png)   | **Mi Router 4C**                      |  R4CM  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R4C.png)    | **Mi Router 4Q**                      |  R4C   | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R4.png)     | **Mi Router 4**                       |   R4   | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R3A.png)    | **Mi Router 3A**                      |  R3A   | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R3L.png)    | **Mi Router 3C**                      |  R3L   | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R3D.png)    | **Mi Router HD**                      |  R3D   | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R3P.png)    | **Mi Router Pro**                     |  R3P   | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R3G.png)    | **Mi Router 3G**                      |  R3G   | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R3.png)     | **Mi Router 3**                       |   R3   | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R2D.png)    | **Mi Router R2D**                     |  R2D   | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R1CL.png)   | **Mi Router Lite**                    |  R1CL  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R1C.png)    | **Mi Router Mini**                    |  R1CM  | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/R1D.png)    | **Mi Router R1D**                     |  R1D   | <sub>🟢🟢🟢🟢⚪</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/RD15.png)    | **Mi Router RD15**                   |  R15   | <sub>🟢🟢🟢🔴🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🔴</sub> |  <sub>🟢🟢🟢🟢🟢</sub>  |
| ![](images/CB0401V2.png) | **Xiaomi 5G CPE Pro CB0401V2**      | CB0401V2 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/CR8816.png) | **Xiaomi Mi Router CR8816**           | CR8816 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RC01.png) | **Mi Router 10000**                     | RC01 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RC06.png) | **Xiaomi Router BE7000**                | RC06 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RD03.png) | **Xiaomi Router AX3000T**               | RD03 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RD08.png) | **Xiaomi Router 6500 Pro**              | RD08 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RD12.png) | **Xiaomi Router AX1500 EU**             | RD12 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RD13.png) | **Xiaomi Mesh System AC1200**           | RD13 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RD16.png) | **Xiaomi BE3600 Gigabit**               | RD16 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RD18.png) | **Xiaomi Router BE5000**                | RD18 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RD23.png) | **Xiaomi Router AX3000T EU**            | RD23 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RD28.png) | **Router Xiaomi RD28 Mesh AX3000 NE**   | RD28 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RN01.png) | **Xiaomi ROUTER BE3600 Pro Black**      | RN01 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢<sub> |
| ![](images/RN02.png) | **Xiaomi Router BE6500**                | RN02 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RN04.png) | **Xiaomi Whole House BE3600 Pro MASTER**| RN04 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RN06.png) | **Xiaomi Mi Router BE3600 2.5G Global** | RN06 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RD04v2.png) | **Xiaomi Router AX1500**              | RD04v2 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>⚪⚪⚪⚪⚪</sub> |
| ![](images/RN07.png) | **Xiaomi Router AX3000T**               | RN07 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/R4ACv2.png) | **Xiaomi 4A Gigabit Edition**         | R4ACv2 | <sub>🟢🟢🟢🟢🔴</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢</sub> |
| ![](images/RC02.png) | **Xiaomi Router AX3000 NE**             | RC02 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>⚪⚪⚪⚪⚪</sub> |
| ![](images/RP04.png) | **Xiaomi Xiaomi BE10000 Pro**           | RP04 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>⚪⚪⚪⚪⚪</sub> |
| ![](images/RD03V2.png) | **Xiaomi Router AX3000T (Qualcomm version).** | RD03V2 | <sub>🟢🟢🟢🟢🟢</sub> | <sub>🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢</sub> | <sub>⚪⚪⚪⚪⚪</sub> |

## 📢 Créditos

Basado en el trabajo original de [@dmamontov](https://github.com/dmamontov/hass-miwifi), adaptado y mejorado para la comunidad hispana por [@JuanManuelRomeroGarcia](https://github.com/JuanManuelRomeroGarcia).

¡Gracias por usar MiWiFi!

---

¿Tienes dudas o sugerencias? Únete al canal de [Telegram de Xiaohack](https://t.me/XiaohackRouters).


## Bundled frontend (HACS)

The panel ships in `custom_components/miwifi/www` and is served at
`/miwifi_static/` using Home Assistant's asynchronous static-path API.
Install this repository as an **Integration** in HACS; no separate dashboard
resource or `panel_custom` YAML entry is needed. Enable the panel through the
existing MiWiFi settings. It remains restricted to administrators.

Frontend source: `Miwifi-panel-frontend` commit `d5f7943` (version `2026.05`).
JavaScript, translations, icons, router images and Lit are included locally.
The panel no longer loads runtime resources from external CDNs. Third-party
licenses are included in `www/vendor/LICENSES.txt`. The bundled panel version
now follows the integration version. Rebuild Lit with `tools/frontend/build.cjs`
after installing the exact dependencies from its lockfile.

Update the integration through HACS and restart Home Assistant to update the
panel. The existing panel update entity only reports the bundled version and
does not install independent updates. Files previously downloaded to
`/config/www/miwifi` and the old stored panel version are left untouched and
are no longer used. Reload the browser after upgrading.

Before publishing, test a fresh HACS installation, an upgrade with old panel
files present, concurrent setup of multiple routers, integration reloads,
panel enable/disable, translations, and removal of the final router.
Check browser requests for missing resources and confirm there are no backend
downloads or periodic checks against the separate frontend repository.
