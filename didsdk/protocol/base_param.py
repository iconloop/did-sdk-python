from dataclasses import dataclass
from typing import Any, Dict


PARAM_VALUE = "value"
PARAM_NONCE = "nonce"


@dataclass(frozen=True)
class BaseParam:
    value: Dict[str, Any]
    nonce: Dict[str, str]
