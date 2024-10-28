from dataclasses import dataclass

from didsdk.jwe.ecdhkey import ECDHKey


@dataclass
class EphemeralPublicKey:
    kid: str
    epk: ECDHKey

    def as_dict(self) -> dict:
        return {"kid": self.kid, "epk": self.epk.as_dict_without_kid()}

    @classmethod
    def from_json(cls, json_data: dict):
        epk = json_data.get("epk")
        if isinstance(epk, dict):
            json_data["epk"] = ECDHKey(**epk)

        return cls(**json_data)

    @classmethod
    def from_ecdh_key(cls, ecdh_key: ECDHKey):
        return cls(kid=ecdh_key.kid, epk=ecdh_key)
