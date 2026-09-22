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

## Panel frontend integrado

Desde la versión **v3.7.0**, el panel frontend de MiWiFi se incluye dentro de esta integración y se instala automáticamente mediante HACS. No es necesario instalar un panel separado ni añadir recursos manualmente.

El repositorio independiente [miwifi-panel-frontend](https://github.com/JuanManuelRomeroGarcia/miwifi-panel-frontend) queda como referencia histórica para instalaciones antiguas; las instalaciones nuevas deben usar este repositorio.
