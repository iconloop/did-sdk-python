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
