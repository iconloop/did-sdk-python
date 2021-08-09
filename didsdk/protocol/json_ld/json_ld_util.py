import secrets
from typing import Any, Dict

from didsdk.core.property_name import PropertyName


def get_types(data: Dict[str, Any]) -> Dict:
    types = data.get(PropertyName.JL_TYPE)
    return types if types else data.get(f'@{PropertyName.JL_TYPE}')


def get_random_nonce(size: int) -> str:
    return str(int(secrets.token_hex(size), 16))[:size]
