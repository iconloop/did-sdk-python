import time
from enum import Enum
from typing import List, Dict, Any, Optional

from coincurve import PublicKey

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.jwt.elements import Payload, Header
from didsdk.jwt.jwt import Jwt, VerifyResult
from didsdk.protocol.json_ld.json_ld_vcr import JsonLdVcr
from didsdk.protocol.json_ld.json_ld_vpr import JsonLdVpr

DEFAULT_TYPE_POSITION = 0
REQ_CREDENTIAL = "REQ_CREDENTIAL"
REQ_PRESENTATION = "REQ_PRESENTATION"
DID_INIT = "DID_INIT"
REQ_REVOCATION = "REQ_REVOCATION"

REQUEST_CLAIM = "requestClaim"


class Type(Enum):
    CREDENTIAL = REQ_CREDENTIAL
    PRESENTATION = REQ_PRESENTATION
    INIT = DID_INIT
    REVOCATION = REQ_REVOCATION


class ClaimRequest:
    """Credential request.

    This class is used when requesting a credential from an issuer or requesting a presentation from holder.
    """
    def __init__(self, jwt: Jwt):
        self.jwt: Jwt = jwt

    @property
    def algorithm(self) -> str:
        return self.jwt.header.alg

    @property
    def claims(self) -> Dict[str, Any]:
        return self.jwt.payload.get(REQUEST_CLAIM)

    @property
    def claim_types(self) -> List[str]:
        types = list(self.jwt.payload.type)
        del types[DEFAULT_TYPE_POSITION]
        return types
    
    @property
    def compact(self) -> str:
        return self.jwt.compact()

    @property
    def did(self) -> str:
        return self.jwt.header.kid.split('#')[0]

    @property
    def key_id(self) -> str:
        return self.jwt.header.kid

    @property
    def kid(self) -> str:
        return self.jwt.header.kid.split('#')[1]

    @property
    def nonce(self) -> str:
        return self.jwt.payload.nonce

    @property
    def public_key(self) -> EphemeralPublicKey:
        return self.jwt.payload.public_key

    @property
    def request_date(self) -> int:
        return self.jwt.payload.iat

    @property
    def request_id(self) -> str:
        return self.jwt.payload.iss

    @property
    def response_id(self) -> str:
        return self.jwt.payload.aud

    @property
    def signature(self) -> str:
        return self.jwt.payload.signature

    @property
    def type(self) -> List[str]:
        return self.jwt.payload.type

    @property
    def vc_id(self) -> str:
        return self.jwt.payload.vc_id

    @property
    def version(self) -> str:
        return self.jwt.payload.version

    @property
    def vcr(self) -> Optional[JsonLdVcr]:
        return self.jwt.payload.vcr

    @property
    def vpr(self) -> Optional[JsonLdVpr]:
        return self.jwt.payload.vpr

    def verify_result_time(self, valid_micro_second: int) -> VerifyResult:
        return self.jwt.verify_iat(valid_micro_second)
    
    def verify(self, public_key: PublicKey) -> VerifyResult:
        return self.jwt.verify(public_key)

    @classmethod
    def from_jwt(cls, jwt: Jwt) -> 'ClaimRequest':
        header: Header = jwt.header
        payload: Payload = jwt.payload

        if not payload.version:
            raise ValueError('version cannot be None.')
        if not payload.type:
            raise ValueError('claimTypes cannot be None.')

        response_id: str = ''
        if payload.aud:
            response_id = payload.aud
        elif payload.sub:
            response_id = payload.sub

        type_ = Type(payload.type[0])
        if not response_id and type_ != Type.PRESENTATION and Type.INIT != type_:
            raise ValueError('responseId cannot be None.')

        algorithm: AlgorithmType = AlgorithmType.from_name(header.alg)
        kid = header.kid
        if not algorithm:
            raise ValueError('algorithm cannot be None.')
        if algorithm != AlgorithmType.NONE and not kid:
            raise ValueError('kid cannot be None.')
        elif type_ != Type.PRESENTATION:
            raise ValueError("NONE type algorithm is only supported when type is presentation")

        return cls(jwt)

    @classmethod
    def from_presentation(cls, jwt: Jwt) -> 'ClaimRequest':
        header: Header = jwt.header
        payload: Payload = jwt.payload

        request_date = payload.iat
        vpr = JsonLdVpr(payload.get(Payload.VPR))
        if not payload.version:
            raise ValueError('version cannot be None.')

        if not vpr:
            raise ValueError('vpr cannot be None.')

        response_id: str = ''
        if payload.aud:
            response_id = payload.aud
        elif payload.sub:
            response_id = payload.sub

        algorithm: AlgorithmType = AlgorithmType.from_name(header.alg)
        did: str = ''
        public_key_id: str = ''
        kid: str = header.kid
        if kid:
            element: list = kid.split('#')
            did = element[0]
            public_key_id = element[1]

        if algorithm != AlgorithmType.NONE:
            if not did:
                raise ValueError('did cannot be None.')
            if not algorithm:
                raise ValueError('algorithm cannot be None.')
            if not public_key_id:
                raise ValueError('publicKeyId cannot be None.')
            if not header.kid:
                kid = did + '#' + public_key_id

        if not request_date:
            request_date = int(time.time() * 1_000_000)

        contents = {
            Payload.ISSUER: did,
            Payload.AUDIENCE: response_id,
            Payload.ISSUED_AT: request_date,
            Payload.PUBLIC_KEY: payload.public_key,
            Payload.CLAIM: {
                Payload.VPR: vpr
            },
            Payload.NONCE: payload.nonce,
            Payload.TYPE: Type.PRESENTATION.value,
            Payload.VERSION: payload.version
        }

        return cls(Jwt(header=Header(alg=algorithm.name, kid=kid),
                       payload=Payload(contents=contents),
                       encoded_token=jwt.encoded_token))
    