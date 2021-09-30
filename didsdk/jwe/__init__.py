from dataclasses import dataclass


@dataclass
class JWEHeader:
    kid: str
    alg: str
    enc: str
