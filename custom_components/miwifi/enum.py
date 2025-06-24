"""Enums."""

from __future__ import annotations

from enum import Enum, IntEnum, StrEnum  # type: ignore

from .const import (
    ATTR_SWITCH_WIFI_2_4,
    ATTR_SWITCH_WIFI_5_0,
    ATTR_SWITCH_WIFI_5_0_GAME,
    ATTR_SWITCH_WIFI_GUEST,
)


class Mode(IntEnum):
    """Mode enum"""

    def __new__(cls, value: int, phrase: str = "undefined") -> "Mode":
        """New mode.

        :param value: int: mode
        :param phrase: str: phrase
        :return Mode
        """

        obj = int.__new__(cls, value)  # type: ignore
        obj._value_ = value

        obj.phrase = phrase  # type: ignore

        return obj

    def __str__(self) -> str:
        """Serialize to string.

        :return str
        """

        return str(self.value)

    DEFAULT = 0, "default"
    REPEATER = 1, "repeater"
    ACCESS_POINT = 2, "access_point"
    MESH_NODE = 3, "mesh_node"
    MESH_LEAF = 8, "mesh_leaf"
    MESH = 9, "mesh"


class Connection(IntEnum):
    """Connection enum"""

    def __new__(cls, value: int, phrase: str = "undefined") -> "Connection":
        """New connection.

        :param value: int: mode
        :param phrase: str: phrase
        :return Connection
        """

        obj = int.__new__(cls, value)  # type: ignore
        obj._value_ = value

        obj.phrase = phrase  # type: ignore

        return obj

    def __str__(self) -> str:
        """Serialize to string.

        :return str
        """

        return str(self.value)

    LAN = 0, "Lan"
    WIFI_2_4 = 1, "2.4G"
    WIFI_5_0 = 2, "5G"
    GUEST = 3, "Guest"
    WIFI_5_0_GAME = 6, "5G Game"


class IfName(str, Enum):
    """IfName enum"""

    def __new__(cls, value: str, phrase: str = "undefined") -> "IfName":
        """New ifname.

        :param value: str: ifname
        :param phrase: str: phrase
        :return IfName
        """

        obj = str.__new__(cls, value)  # type: ignore
        obj._value_ = value

        obj.phrase = phrase  # type: ignore

        return obj

    def __str__(self) -> str:
        """Serialize to string.

        :return str
        """

        return str(self.value)

    WL0 = "wl0", ATTR_SWITCH_WIFI_5_0
    WL1 = "wl1", ATTR_SWITCH_WIFI_2_4
    WL2 = "wl2", ATTR_SWITCH_WIFI_5_0_GAME
    WL14 = "wl14", ATTR_SWITCH_WIFI_GUEST


class Wifi(IntEnum):
    """Wifi enum"""

    def __new__(cls, value: int, phrase: str = "undefined") -> "Wifi":
        """New Wifi.

        :param value: int: WifiIndex
        :param phrase: str: phrase
        :return Wifi
        """

        obj = int.__new__(cls, value)  # type: ignore
        obj._value_ = value

        obj.phrase = phrase  # type: ignore

        return obj

    def __str__(self) -> str:
        """Serialize to string.

        :return str
        """

        return str(self.value)

    ADAPTER_2_4 = 1, ATTR_SWITCH_WIFI_2_4
    ADAPTER_5_0 = 2, ATTR_SWITCH_WIFI_5_0
    ADAPTER_5_0_GAME = 3, ATTR_SWITCH_WIFI_5_0_GAME


class DeviceAction(IntEnum):
    """DeviceAction enum"""

    def __new__(cls, value: int, phrase: str = "undefined") -> "DeviceAction":
        """New device action.

        :param value: int: action
        :param phrase: str: phrase
        :return DeviceAction
        """

        obj = int.__new__(cls, value)  # type: ignore
        obj._value_ = value

        obj.phrase = phrase  # type: ignore

        return obj

    def __str__(self) -> str:
        """Serialize to string.

        :return str
        """

        return str(self.value)

    ADD = 0, "Add"
    MOVE = 1, "Move"
    SKIP = 2, "Skip"


class EncryptionAlgorithm(StrEnum):
    """EncryptionAlgorithm enum"""

    SHA1 = "sha1"
    SHA256 = "sha256"


class DeviceClass(StrEnum):
    """DeviceClass enum"""

    MODE = "miwifi__mode"
    SIGNAL_STRENGTH = "miwifi__signal_strength"
    DEVICE_TRACKER = "miwifi__device_tracker"


class Model(str, Enum):
    """Model enum"""

    def __new__(cls, value: str) -> "Model":
        """New Model.

        :param value: str: Model
        :return Model
        """

        obj = str.__new__(cls, value)  # type: ignore
        obj._value_ = value

        return obj

    def __str__(self) -> str:
        """Serialize to string.

        :return str
        """

        return str(self.value)

    NOT_KNOWN = "not_known"
    
    # CB Series
    
    CB0401 = "cb0401"  # Xiaomi Mi Router CB0401 2022
    CB0401V2 = "cb0401v2" # Xiaomi 5G CPE Pro CB0401V2 
    
    # CR Series
    
    CR6606 = "cr6606"  # Xiaomi Mi Router CR6606​ 2021.04.25
    CR8808 = "cr8808"  # Xiaomi Mi Router CR8808 2021.11.26
    CR8816 = "cr8816"  # Xiaomi Mi Router CR8816 
    CR8806 = "cr8806"  # Xiaomi Mi Router CR8806 2021.11.26
    
    # D Series
    
    D01 = "d01"  # Xiaomi Mesh Router D01 2019.11.26
    
    # R Series
    
    R1CL = "r1cl"  #  Xiaomi Mi Router 3 2015
    R1CM = "r1cm"  # Xiaomi Mi Router 3C 2014
    R1D = "r1d"  # Xiaomi MiWiFi R1D 2014
    R2D = "r2d"  # Xiaomi MiWiFi R2D​ 2015.08
    R3 = "r3"  # Xiaomi Mi Router 3​ 2016
    R3A = "r3a"  # Xiaomi Mi Router 3A 2017.11.16
    R3D = "r3d"  # Xiaomi MiWiFi HD 2017
    R3G = "r3g"  # Xiaomi Mi Router 3G 2017.03
    R3L = "r3l"  # Xiaomi Mi Router 3 Lite 2017
    R3P = "r3p"  # Xiaomi Mi Router Pro 2017
    R4 = "r4"  # Xiaomi Mi Router 4​ 2019.11.26
    R4A = "r4a"  # Xiaomi Mi Router 4A 2019.11.26
    R4AC = "r4ac"  # Xiaomi Mi Router 4A Gigabit Edition​ 2019.11.26
    R4AV2 = "r4av2"  # Xiaomi Mi Router 4A (Versión 2)​ 2022
    R4C = "r4c"  # Xiaomi Mi Router 4C 2019.11.26
    R4CM = "r4cm"  # Xiaomi Mi Router 4C 2019.11.26
    R2100 = "r2100"  # Xiaomi Mi Router AC2100 2019.11.26
    R2350 = "r2350"  #  Xiaomi Mi AIoT Router AC2350 2020.07.02
    R1350 = "r1350"  # Xiaomi Mi Router 4A​ 2020.07.03
    R3600 = "r3600"  # Xiaomi Mi AIoT Router AX3600 2020.03.01
    
    # RA Series
    
    RA50 = "ra50"  # Xiaomi Mi Router AX1800 2021.01.28
    RA67 = "ra67"  # Redmi Router AX6 2020.06.19
    RA69 = "ra69"  # Redmi Router AX6​ 2020.08.11
    RA70 = "ra70"  # Xiaomi Mi Router AX1800 2021.03.30
    RA71 = "ra71"  # Xiaomi Mi Router AX1800 2021.10.22
    RA72 = "ra72"  # Xiaomi Mi Router AX1800 2021.01.08
    RA74 = "ra74"  # Redmi Router AX5400 2022.03.18
    RA80 = "ra80"  # Xiaomi Mi Router AX3000 2021.08.11
    RA80V2 = "ra80v2" # Xiaomi AX3000 (CN)
    RA81 = "ra81"  # Xiaomi Mi Router AX3000T 2021.07.27
    RA82 = "ra82"  # Xiaomi Mi Router AX3000 2021.11.01
    
    # RB Series
    
    RB01 = "rb01"  # Redmi Router AX5​ 2021.10.28
    RB02 = "rb02"  #  Xiaomi Mi Router AC1200​ 2022.01.18
    RB03 = "rb03"  # Redmi Router AX6S​ 2021.09.27
    RB04 = "rb04"  # Redmi Router AX5400 Gaming 2022.02.17
    RB06 = "rb06"  # Redmi Router AX6S​ 2022.04.02
    RB08 = "rb08"  # Redmi Router AX6S 2022.07.04
    
    # RC Series
    
    RC01 = "rc01"  # Mi Router 10000
    RC06 = "rc06"  # Xiaomi Router BE7000
    
    # RD Series
    
    RD03 = "rd03"  # Xiaomi Router AX3000T
    RD04v2 = "rd04v2"  # Xiaomi Router AX1500
    RD08 = "rd08"  # Xiaomi Router 6500 Pro
    RD12 = "rd12"  # Xiaomi Router AX1500 EU
    RD13 = "rd13"  # Xiaomi Mesh System AC1200
    RD15 = "rd15"  # Xiaomi Mi Router BE3600 2,5G
    RD16 = "rd16"  # Xiaomi BE3600 Gigabit
    RD18 = "rd18"  # Xiaomi Router BE5000 
    RD23 = "rd23"  # Xiaomi Router AX3000T EU
    RD28 = "rd28"  # Router Xiaomi RD28 Mesh AX3000 NE
    
    # RM Series
    
    RM1800 = "rm1800"  # Redmi Router AX5 2020.05
    RM2100 = "rm2100"  # Redmi Router AC2100 2019
    
    # RN Series
    
    RN01 = "rn01" # Xiaomi ROUTER BE3600 Pro Black
    RN02 = "rn02" # Xiaomi Router BE6500
    RN04 = "rn04" # Xiaomi Whole House BE3600 Pro MASTER
    RN06 = "rn06" # Xiaomi Mi Router BE3600 2.5G (Versión Global)
    RN07 = "rn07" # Xiaomi router AX3000E
