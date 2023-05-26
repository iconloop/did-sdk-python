from typing import Dict, List, Optional

from didsdk.jwt.convert_jwt import ConvertJwt
from didsdk.jwt.elements import Header, Payload
from didsdk.jwt.issuer_did import IssuerDid
from didsdk.jwt.jwt import Jwt
from didsdk.protocol.base_claim import BaseClaim
from didsdk.protocol.json_ld.json_ld_param import JsonLdParam
from didsdk.protocol.json_ld.json_ld_vc import JsonLdVc
from didsdk.protocol.json_ld.revocation_service import RevocationService


class CredentialVersion:
    v1_0 = "1.0"
    v1_1 = "1.1"
    v2_0 = "2.0"


class Credential(ConvertJwt):
    """This class to create a verifiable credential.

    IT can be used to express information that a credential represents.
    (for example, a city government, national agency, or identification number)

    For credential to be verifiable, proof mechanism use Json Web Token.
    You can generate a complete JWT (with Signature) by calling `didsdk.core.did_key_holder.sign(Jwt)`.

    A credential is a set of one or more claims.
    It might also include metadata to describe properties of the credential, such as the issuer,
    the expiry time, the issued time, an algorithm for verification, and so on.

    These claims and metadata must be signed by the issuer.
    After that, you can generate `didsdk.presentation.Presentation`.
    """

    EXP_DURATION: int = 24 * 60 * 60  # second
    DEFAULT_TYPE: str = "CREDENTIAL"

    def __init__(
        self,
        algorithm: str,
        key_id: str,
        did: str,
        version: str,
        id_: str = None,
        target_did: str = None,
        claim: dict = None,
        jti: str = None,
        nonce: str = None,
        vc_id: str = None,
        base_claim: BaseClaim = None,
        refresh_id: str = None,
        refresh_type: str = None,
        revocation_service: RevocationService = None,
        terms_of_use: List[Dict[str, str]] = None,
        param: JsonLdParam = None,
        vc: JsonLdVc = None,
        jwt: Jwt = None,
    ):
        self._algorithm: str = algorithm
        self._key_id: str = key_id
        self._did: str = did
        self.claim: dict = claim if claim else {}
        self._base_claim: BaseClaim = base_claim if base_claim else None
        self._vc: JsonLdVc = vc if vc else None
        self.vc_id: str = vc_id
        self.nonce: str = nonce
        self.jti: str = jti
        self._json_ld_param: Optional[JsonLdParam] = None

        self.version: str = CredentialVersion.v1_1 if base_claim else version
        if param and self.version is None:
            self.version = CredentialVersion.v2_0

        if not self.version:
            raise ValueError("version cannot be None.")
        self.target_did: str = target_did

        if claim:
            if self.version == CredentialVersion.v1_1:
                self._base_claim = BaseClaim.from_json(claim)
        elif base_claim:
            self._base_claim = base_claim
        elif param:
            self._json_ld_param = param
            self._vc = JsonLdVc.from_(
                id_=id_,
                credential_subject_id=self.target_did,
                param=param,
                refresh_id=refresh_id,
                refresh_type=refresh_type,
                revocation_service=revocation_service,
                terms_of_use=terms_of_use,
            )

        self.jwt: Jwt = jwt

    @property
    def algorithm(self):
        return self._algorithm

    @property
    def did(self):
        return self._did

    @property
    def duration(self) -> int:
        return self.EXP_DURATION

    @property
    def key_id(self):
        return self._key_id

    @property
    def base_claim(self):
        """deprecated: only for version 1.1"""
        return self._base_claim if self._check_version(CredentialVersion.v1_1) else None

    @property
    def vc(self):
        return self._vc if self._check_version(CredentialVersion.v2_0) else None

    @property
    def param(self):
        return self._json_ld_param if self._check_version(CredentialVersion.v2_0) else None

    def add_claim(self, type_: str, value: str):
        """Add the information that express the owner's credential.

        :param type_: the type of claim (email, phone, gender)
        :param value: the value of claim (abc@abc.com, 01012345678, M)
        :return:
        """
        self.claim[type_] = value

    def as_jwt(self, issued: int, expiration: int) -> Jwt:
        contents = {
            Payload.ISSUER: self.did,
            Payload.ISSUED_AT: issued,
            Payload.EXPIRATION: expiration,
            Payload.SUBJECT: self.target_did,
            Payload.NONCE: self.nonce,
            Payload.JTI: self.jti,
            Payload.TYPE: self.get_types(),
            Payload.VC_ID: self.vc_id,
            Payload.VERSION: self.version,
        }
        kid = self.did + "#" + self.key_id
        if self.version in [CredentialVersion.v1_0, CredentialVersion.v1_1]:
            if self._base_claim:
                self.claim = self._base_claim.to_json()

            contents[Payload.CLAIM] = self.claim
        elif self.version == CredentialVersion.v2_0:
            if not self._vc:
                raise ValueError("VC cannot be None.")

            contents[Payload.VC] = self._vc.as_dict()
        else:
            raise ValueError("Unsupported version.")

        header = Header(alg=self.algorithm, kid=kid)
        payload = Payload(contents=contents)
        return Jwt(header, payload)

    @staticmethod
    def from_encoded_jwt(encoded_jwt: str) -> "Credential":
        """Returns the credential object representation of the Jwt argument.

        :param encoded_jwt: the JWT with properties of the Credential object
        :return:
        """
        return Credential.from_jwt(Jwt.decode(encoded_jwt))

    @staticmethod
    def from_jwt(jwt: Jwt) -> "Credential":
        """Returns the credential object representation of the String argument.

        :param jwt: encodedJwt the String returned by calling `didsdk.core.did_key_holder.sign(Jwt)`.
        :return: the credential object from jwt
        """
        payload = jwt.payload
        issuer_did = IssuerDid.from_jwt(jwt)
        return Credential(
            algorithm=issuer_did.algorithm,
            key_id=issuer_did.key_id,
            did=issuer_did.did,
            target_did=payload.sub,
            claim=payload.claim,
            vc_id=payload.vc_id,
            vc=payload.vc,
            nonce=payload.nonce,
            jwt=jwt,
            jti=payload.jti,
            version=payload.version,
        )

    def get_types(self) -> list:
        types = [self.DEFAULT_TYPE]
        if self.version:
            if self.version == CredentialVersion.v1_0:
                return types + list(self.claim.keys())
            if self.version == CredentialVersion.v1_1:
                return types + list(self.base_claim.attribute.hashed_values.keys())

        return types

    def _check_version(self, version: str) -> bool:
        return self.version and self.version == version
