from typing import List, Optional

from didsdk.credential import Credential, CredentialVersion
from didsdk.jwt.convert_jwt import ConvertJwt
from didsdk.jwt.elements import Header, Payload
from didsdk.jwt.issuer_did import IssuerDid
from didsdk.jwt.jwt import Jwt
from didsdk.protocol.base_vc import BaseVc
from didsdk.protocol.json_ld.json_ld_vp import JsonLdVp


class Presentation(ConvertJwt):
    """This class use to create a verifiable presentation.

    A verifiable presentation expresses data from one or more credentials, and is packaged in
    such a way that the authorship of the data is verifiable.

    This object must be signed by the owner of the credential.
    And you can send a specific verifier.

    The verifier can verify the authenticity of the presentation and credentials,
    and also verify that the owner possesses the credential
    """

    EXP_DURATION: int = 5 * 60          # second
    DEFAULT_TYPE: str = 'PRESENTATION'

    def __init__(self, issuer_did: IssuerDid, base_vcs: List[BaseVc] = None):
        self._issuer_did: IssuerDid = issuer_did
        self._credentials: list = []
        self._jwt: Optional[Jwt] = None
        self._types: List[str] = []
        self._vp: Optional[JsonLdVp] = None
        self.nonce: Optional[str] = None
        self.jti: Optional[str] = None
        self.version: Optional[str] = None
        self.base_vcs: List[BaseVc] = base_vcs if base_vcs else []

    @property
    def algorithm(self) -> str:
        return self._issuer_did.algorithm

    @property
    def credentials(self) -> list:
        return self._credentials

    @credentials.setter
    def credentials(self, credentials: list):
        """Set the list of credential. Use only version  1.0,  1.1.

        :param credentials: the list of credential
        :return:
        """
        self._types = []
        for credential in credentials:
            self.add_credential(credential)

    @property
    def did(self) -> str:
        return self._issuer_did.did

    @property
    def duration(self) -> int:
        return self.EXP_DURATION

    @property
    def issuer_did(self) -> IssuerDid:
        return self._issuer_did

    @property
    def jwt(self) -> Jwt:
        return self._jwt

    @property
    def key_id(self) -> str:
        return self._issuer_did.key_id

    @property
    def vp(self) -> JsonLdVp:
        return self._vp

    def add_credential(self, credential: str):
        """Add the credential

        :param credential: the credential signed by issuer, the string is the encoded jwt
        :return:
        """
        self._credentials.append(credential)
        credential = Credential.from_encoded_jwt(credential)
        types = credential.get_types()
        types.remove(Credential.DEFAULT_TYPE)
        self._types += types

    def as_jwt(self, issued: int, expiration: int) -> Jwt:
        kid = self.did + '#' + self.key_id
        header = Header(alg=self.algorithm, kid=kid)
        contents = {
            Payload.ISSUER: self.did,
            Payload.ISSUED_AT: issued,
            Payload.EXPIRATION: expiration,
            Payload.CLAIM: self._credentials,
            Payload.NONCE: self.nonce,
            Payload.JTI: self.jti,
            Payload.TYPE: self.get_types(),
            Payload.VERSION: self.version
        }
        payload = Payload(contents=contents)
        return Jwt(header, payload)

    @staticmethod
    def from_(issuer_did: IssuerDid,
              credentials: list,
              vp: JsonLdVp,
              nonce: str,
              version: str,
              jwt: Jwt) -> 'Presentation':

        if not version:
            raise ValueError('version cannot None.')

        presentation = Presentation(issuer_did)
        if credentials:
            presentation.credentials = credentials
        if vp:
            presentation._vp = vp
        presentation.nonce = nonce
        presentation.version = version
        presentation._jwt = jwt
        presentation.jti = jwt.payload.jti

        return presentation

    @staticmethod
    def from_encoded_jwt(encoded_jwt: str) -> 'Presentation':
        """Returns the presentation object representation of the Jwt argument.

        :param encoded_jwt: the JWT with properties of the Credential object
        :return: the presentation object from encoded jwt
        """
        return Presentation.from_jwt(Jwt.decode(encoded_jwt))

    @staticmethod
    def from_jwt(jwt: Jwt) -> 'Presentation':
        """Returns the presentation object representation of the String argument.

        :param jwt: encodedJwt the String returned by calling `didsdk.core.did_key_holder.sign(Jwt)`.
        :return: the presentation object from jwt
        """
        payload = jwt.payload
        issuer_did = IssuerDid.from_jwt(jwt)
        return Presentation.from_(issuer_did, payload.credential, payload.vp, payload.nonce, payload.version, jwt)

    def get_plain_params(self, key: str) -> list:
        """get claim values from Presentation VC

        :param key: a claim name
        :return:
        """
        if CredentialVersion.v1_1 == self.version:
            return [base_vc for base_vc in self.base_vcs if key in base_vc.vc_type]
        elif CredentialVersion.v2_0 == self.version:
            return [criteria.param.claims[key].claim_value
                    for criteria in self.vp.fulfilledCriteria if key in criteria.param.claims]

    def get_types(self):
        return [self.DEFAULT_TYPE] + self._types
