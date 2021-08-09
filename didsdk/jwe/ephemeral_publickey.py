from dataclasses import dataclass

from didsdk.jwe.ecdhkey import ECDHKey


@dataclass
class EphemeralPublicKey:
    kid: str
    epk: ECDHKey
