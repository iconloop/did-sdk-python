import time
from typing import List, Dict, Any, Optional

from coincurve import PublicKey

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.jwt.elements import Payload, Header
from didsdk.jwt.jwt import Jwt, VerifyResult
from didsdk.protocol.claim_message_type import ClaimRequestType
from didsdk.protocol.json_ld.json_ld_vcr import JsonLdVcr
from didsdk.protocol.json_ld.json_ld_vpr import JsonLdVpr

DEFAULT_TYPE_POSITION = 0
REQUEST_CLAIM = "requestClaim"


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

    def verify_result_time(self, valid_micro_second: int = None) -> VerifyResult:
        return self.jwt.verify_iat(valid_micro_second)
    
    def verify(self, public_key: PublicKey) -> VerifyResult:
        return self.jwt.verify(public_key)

    @classmethod
    def from_(cls, type_: ClaimRequestType,
              did: str,
              algorithm: AlgorithmType,
              public_key_id: str,
              version: str,
              request_date: int = None,
              expired_date: int = None,
              kid: str = None,
              public_key: EphemeralPublicKey = None,
              vc_id: str = None,
              claims: dict = None,
              vcr: JsonLdVcr = None,
              vpr: JsonLdVpr = None,
              nonce: str = None,
              jti: str = None,
              encoded_token: List[str] = None,
              response_id: str = None) -> 'ClaimRequest':
        if not version:
            raise ValueError('version cannot be None.')
        if not response_id and (type_ not in [ClaimRequestType.REQ_PRESENTATION, ClaimRequestType.DID_INIT]):
            raise ValueError('responseId cannot be None.')

        if algorithm != AlgorithmType.NONE:
            if not did:
                raise ValueError('did cannot be None.')
            if not algorithm:
                raise ValueError('algorithm cannot be None.')
            if not public_key_id:
                raise ValueError('publicKeyId cannot be None.')
            if not kid:
                kid = did + '#' + public_key_id
        elif type_ != ClaimRequestType.REQ_PRESENTATION:
            raise ValueError(f'None algorithm is supported only for presentation.')

        if not request_date:
            request_date = int(time.time() * 1_000_000)

        header: Header = Header(alg=algorithm.name, kid=kid)
        contents = {
            Payload.ISSUER: did,
            Payload.AUDIENCE: response_id,
            Payload.ISSUED_AT: request_date,
            Payload.EXPIRATION: expired_date,
            REQUEST_CLAIM: claims,
            Payload.TYPE: [type_.value],
            Payload.PUBLIC_KEY: public_key.as_dict() if public_key else None,
            Payload.NONCE: nonce,
            Payload.JTI: jti,
            Payload.VC_ID: vc_id,
            Payload.VCR: vcr.as_dict() if vcr else None,
            Payload.VPR: vpr.as_dict() if vpr else None,
            Payload.VERSION: version
        }
        payload = Payload(contents=contents)
        return cls(Jwt(header=header, payload=payload, encoded_token=encoded_token))

    @classmethod
    def for_did(cls, algorithm: AlgorithmType,
                did: str,
                public_key_id: str,
                response_id: str,
                version: str,
                type_: ClaimRequestType,
                nonce: str,
                kid: str = None,
                request_date: int = None,
                encoded_token: List[str] = None,
                jti: str = None,
                public_key: EphemeralPublicKey = None):
        if not version:
            raise ValueError('version cannot be None.')
        if not response_id and type_ != ClaimRequestType.REQ_PRESENTATION and type_ != ClaimRequestType.DID_INIT:
            raise ValueError('responseId cannot be None.')

        if algorithm != AlgorithmType.NONE:
            if not did:
                raise ValueError('did cannot be None.')
            if not algorithm:
                raise ValueError('algorithm cannot be None.')
            if not public_key_id:
                raise ValueError('publicKeyId cannot be None.')
            if not kid:
                kid = did + '#' + public_key_id

        if not request_date:
            request_date = int(time.time() * 1_000_000)

        contents = {
            Payload.ISSUER: did,
            Payload.AUDIENCE: response_id,
            Payload.ISSUED_AT: request_date,
            Payload.PUBLIC_KEY: public_key.as_dict() if public_key else None,
            Payload.NONCE: nonce,
            Payload.TYPE: [type_.value],
            Payload.jti: jti,
            Payload.VERSION: version
        }

        return cls(Jwt(header=Header(alg=algorithm.name, kid=kid),
                       payload=Payload(contents=contents),
                       encoded_token=encoded_token))

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

        type_ = ClaimRequestType(payload.type[0])
        if not response_id and type_ != ClaimRequestType.REQ_PRESENTATION and ClaimRequestType.DID_INIT != type_:
            raise ValueError('responseId cannot be None.')

        algorithm: AlgorithmType = AlgorithmType.from_name(header.alg)
        kid = header.kid
        if not algorithm:
            raise ValueError('algorithm cannot be None.')
        if algorithm != AlgorithmType.NONE:
            if not kid:
                raise ValueError('kid cannot be None.')
        elif type_ != ClaimRequestType.REQ_PRESENTATION:
            raise ValueError(f'None algorithm is supported only for presentation.')

        return cls(jwt)

    @classmethod
    def for_presentation(cls, algorithm: AlgorithmType,
                         did: str,
                         public_key_id: str,
                         response_id: str,
                         public_key: EphemeralPublicKey,
                         nonce: str,
                         version: str,
                         vpr: JsonLdVpr=None,
                         kid: str = None,
                         encoded_token: List[str] = None,
                         jti: str = None,
                         request_date: int = None,
                         expired_date: int = None):
        return cls.from_(ClaimRequestType.REQ_PRESENTATION,
                         did=did,
                         algorithm=algorithm,
                         public_key_id=public_key_id,
                         response_id=response_id,
                         vpr=vpr,
                         public_key=public_key,
                         nonce=nonce,
                         version=version,
                         kid=kid,
                         encoded_token=encoded_token,
                         jti=jti,
                         request_date=request_date,
                         expired_date=expired_date)

    @classmethod
    def for_presentation_from_jwt(cls, jwt: Jwt) -> 'ClaimRequest':
        header: Header = jwt.header
        payload: Payload = jwt.payload

        request_date = payload.iat
        vpr = payload.get(Payload.VPR)

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
            Payload.PUBLIC_KEY: payload.public_key.as_dict(),
            Payload.CLAIM: {
                Payload.VPR: vpr
            },
            Payload.NONCE: payload.nonce,
            Payload.TYPE: ClaimRequestType.REQ_PRESENTATION.value,
            Payload.VERSION: payload.version
        }

        return cls(Jwt(header=Header(alg=algorithm.name, kid=kid),
                       payload=Payload(contents=contents),
                       encoded_token=jwt.encoded_token))

    @classmethod
    def for_revocation(cls, algorithm: AlgorithmType,
                       did: str,
                       public_key_id: str,
                       response_id: str,
                       signature: str,
                       version: str,
                       type_: ClaimRequestType = None,
                       kid: str = None,
                       request_date: int = None) -> 'ClaimRequest':
        if not (version and response_id and signature):
            raise ValueError(f'Any value in [version, responseId, signature] cannot be None.')

        if algorithm != AlgorithmType.NONE:
            if not did:
                raise ValueError('did cannot be None.')
            if not algorithm:
                raise ValueError('algorithm cannot be None.')
            if not public_key_id:
                raise ValueError('publicKeyId cannot be None.')
            if not kid:
                kid = did + '#' + public_key_id
        elif type_ != ClaimRequestType.REQ_PRESENTATION:
            raise ValueError(f'None algorithm is supported only for presentation.')

        if not request_date:
            request_date = int(time.time()*1_000_000)

        type_ = [ClaimRequestType.REQ_REVOCATION.value, type_.value] if type_ else [ClaimRequestType.REQ_REVOCATION.value]

        header: Header = Header(alg=algorithm.name, kid=kid)
        contents = {
            Payload.ISSUER: did,
            Payload.AUDIENCE: response_id,
            Payload.ISSUED_AT: request_date,
            Payload.SIGNATURE: signature,
            Payload.TYPE: type_,
            Payload.VERSION: version
        }
        payload = Payload(contents=contents)
        return cls(Jwt(header=header, payload=payload))
