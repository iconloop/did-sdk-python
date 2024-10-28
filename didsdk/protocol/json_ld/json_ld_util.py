import json
import secrets
from typing import Any, Dict, Optional

from didsdk.core.property_name import PropertyName


def as_bytes(value, encoding: str = "utf-8") -> Optional[bytes]:
    if isinstance(value, str):
        return value.encode(encoding)
    elif isinstance(value, (dict, list)):
        return json.dumps(value).encode(encoding)
    elif isinstance(value, int):
        return int.to_bytes(value, length=32, byteorder="big")
    elif isinstance(value, bool):
        return value.to_bytes(length=32, byteorder="big")
    else:
        return None


def get_types(data: Dict[str, Any]) -> Dict:
    types = data.get(PropertyName.JL_TYPE)
    return types if types else data.get(f"@{PropertyName.JL_TYPE}")


def get_random_nonce(size: int) -> str:
    return str(int(secrets.token_hex(size), 16))[:size]
