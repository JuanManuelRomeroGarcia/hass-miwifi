"""Unsupported models registry."""

from __future__ import annotations

from .enum import Model

UNSUPPORTED: dict[str, list[Model]] = {
    "new_status": [
        Model.R1D,
        Model.R2D,
        Model.R1CM,
        Model.R1CL,
        Model.R3P,
        Model.R3D,
        Model.R3L,
        Model.R3A,
        Model.R3,
        Model.R3G,
        Model.R4,
        Model.R4A,
        Model.R4AC,
        Model.R4C,
        Model.R4CM,
        Model.D01,
        Model.RN06,
    ],
    
    "wifi_config": [
        Model.CR8806,
    ],

    "mac_filter": [],
    
    "mac_filter_info":[
        Model.RM1800,
    ],

    "qos_info": [],
    "vpn_control": [],
}
