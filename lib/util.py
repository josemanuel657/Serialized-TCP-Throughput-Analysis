# CONSTANTS

from dataclasses import dataclass
from typing import Optional


DEFAULT_PORT = "5201"
DEFAULT_WAIT_FOR_SERVER_START = 2.5  # In seconds


@dataclass
class RunConfig:
    """
    A class that represents the configuration for a single run of the test.

    If iPerfSize is not specified, the size of the iPerf test will be limited by iPerfTime.
    If iPerfSize is specified, the iPerf test will ignore iPerfTime.

    Fields:
        hystartEnabled: Whether to enable hystart. Default: True
        searchMode: The search mode to use. 0: disabled, 1: enabled with exit, 2: enabled without exit (just logging) Default: 2
        iPerfTime: The time to run the iPerf test for. Default: 10
        iPerfSize: The size of the iPerf test in bytes. Default: limited by iPerfTime
    """

    hystartEnabled: bool = True
    searchMode: str = 2
    iPerfTime: int = 10
    iPerfSize: int = None

    def to_dict(self):
        return {
            "hystartEnabled": self.hystartEnabled,
            "searchMode": self.searchMode,
            "iPerfTime": self.iPerfTime,
            "iPerfSize": self.iPerfSize,
        }


def int_or_none(value: str) -> Optional[int]:
    try:
        return int(value)
    except ValueError:
        return None
