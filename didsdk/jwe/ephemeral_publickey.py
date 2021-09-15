import dataclasses
from dataclasses import dataclass

from didsdk.jwe.ecdhkey import ECDHKey


@dataclass
class EphemeralPublicKey:
    kid: str
    epk: ECDHKey

    def as_dict(self) -> dict:
        return {
            'kid': self.kid,
            'epk': dataclasses.asdict(self.epk)
        }

    @classmethod
    def from_json(cls, json_data: dict):
        epk = json_data.get('epk')
        if isinstance(epk, dict):
            json_data['epk'] = ECDHKey(**epk)

        return cls(**json_data)
    