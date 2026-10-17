"""Luci API client exceptions."""


class LuciError(BaseException):
    """Luci error"""

    def __init__(self, *args, response=None):
        super().__init__(*args)
        self.response = response


class LuciConnectionError(LuciError):
    """Luci connection error"""


class LuciRequestError(LuciError):
    """Luci request error"""
