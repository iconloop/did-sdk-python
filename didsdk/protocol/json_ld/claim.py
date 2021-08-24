import json
from dataclasses import dataclass
from typing import Any

from didsdk.core.property_name import PropertyName
from didsdk.protocol.json_ld import json_ld_util


@dataclass
class Claim:
    claim_value: Any
    display_value: str = None
    salt: str = None

    def as_json(self) -> str:
        claims = {
            PropertyName.JL_CLAIM_VALUE: self.claim_value,
            PropertyName.JL_SALT: self.salt
        }

        if self.display_value:
            claims[PropertyName.JL_DISPLAY_VALUE] = self.display_value

        return json.dumps(claims)

    def claim_value_as_bytes(self, encoding='utf-8') -> bytes:
        return json_ld_util.as_bytes(self.claim_value, encoding)
