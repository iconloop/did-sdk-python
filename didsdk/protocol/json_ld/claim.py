from dataclasses import dataclass
from typing import Any

from didsdk.core.property_name import PropertyName
from didsdk.protocol.json_ld import json_ld_util


@dataclass
class Claim:
    claim_value: Any
    display_value: str = None
    salt: str = None

    def __str__(self):
        return str(self.claim_value)

    def as_dict(self) -> dict:
        claims = {PropertyName.JL_CLAIM_VALUE: self.claim_value, PropertyName.JL_SALT: self.salt}

        if self.display_value:
            claims[PropertyName.JL_DISPLAY_VALUE] = self.display_value

        return claims

    def claim_value_as_bytes(self, encoding: str = "utf-8") -> bytes:
        return json_ld_util.as_bytes(self.claim_value, encoding)

    @classmethod
    def from_json(cls, json_data: dict):
        return cls(
            claim_value=json_data[PropertyName.JL_CLAIM_VALUE],
            display_value=json_data.get(PropertyName.JL_DISPLAY_VALUE),
            salt=json_data.get(PropertyName.JL_SALT),
        )
