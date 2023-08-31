from dataclasses import dataclass
from typing import Dict

PARAM_VALUE = "value"
PARAM_NONCE = "nonce"


@dataclass(frozen=True)
class BaseParam:
    value: dict
    nonce: Dict[str, str]
