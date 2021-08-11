from didsdk.credential import Credential
from didsdk.jwt.convert_jwt import ConvertJwt
from didsdk.jwt.elements import Header, Payload
from didsdk.jwt.issuer_did import IssuerDid
from didsdk.jwt.jwt import Jwt


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

    def __init__(self, issuer_did: IssuerDid, jti: str = None, nonce: str = None, version: str = None):
        self._issuer_did = issuer_did
        self._credentials: list = []
        self._types: list = []
        self.nonce: str = nonce
        self.jti: str = jti
        self.version: str = version

    @property
    def algorithm(self):
        return self._issuer_did.algorithm

    @property
    def credentials(self) -> list:
        return self._credentials

    @credentials.setter
    def credentials(self, credentials: list):
        self._types = []
        for credential in credentials:
            self.add_credential(credential)

    @property
    def did(self):
        return self._issuer_did.did

    @property
    def duration(self) -> int:
        return self.EXP_DURATION

    @property
    def issuer_did(self):
        return self._issuer_did

    @property
    def key_id(self):
        return self._issuer_did.key_id

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
        presentation = Presentation(issuer_did, nonce=payload.nonce, jti=payload.jti, version=payload.version)
        presentation.credentials = payload.credential
        return presentation

    def get_types(self):
        return [self.DEFAULT_TYPE] + self._types
