import json
from dataclasses import dataclass
from typing import Any

from didsdk.core.property_name import PropertyName


@dataclass
class Claim:
    claim_value: Any
    display_value: str
    salt: str = None

    def to_json(self) -> str:
        claims = {
            PropertyName.JL_CLAIM_VALUE: self.claim_value,
            PropertyName.JL_SALT: self.salt
        }

        if self.display_value:
            claims[PropertyName.JL_DISPLAY_VALUE] = self.display_value

        return json.dumps(claims)
