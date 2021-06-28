from didsdk.jwt.convert_jwt import ConvertJwt
from didsdk.jwt.elements import Header, Payload
from didsdk.jwt.issuer_did import IssuerDid
from didsdk.jwt.jwt import Jwt


class Credential(ConvertJwt):
    """This class to create a verifiable credential, which can be used to express information that a credential represents.

    (for example, a city government, national agency, or identification number)

    For credential to be verifiable, proof mechanism use Json Web Token.
    You can generate a complete JWT (with Signature) by calling `didsdk.core.did_key_holder.sign(Jwt)`.

    A credential is a set of one or more claims.
    It might also include metadata to describe properties of the credential, such as the issuer,
    the expiry time, the issued time, an algorithm for verification, and so on.

    These claims and metadata must be signed by the issuer.
    After that, you can generate `didsdk.presentation.Presentation`.
    """

    EXP_DURATION: int = 24 * 60 * 60        # second
    DEFAULT_TYPE: str = 'CREDENTIAL'

    def __init__(self, issuer_did: IssuerDid, target_did: str = None, claim=None,
                 jti: str = None, nonce: str = None, version: str = None):
        if claim is None:
            claim = {}
        self._issuer_did: IssuerDid = issuer_did

        self.claim: dict = claim if claim else {}
        self.nonce: str = nonce
        self.jti: str = jti
        self.target_did: str = target_did
        self.version: str = version

    @property
    def algorithm(self):
        return self._issuer_did.algorithm

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

    def add_claim(self, type_: str, value: str):
        """Add the information that express the owner's credential.

        :param type_: the type of claim (email, phone, gender)
        :param value: the value of claim (abc@abc.com, 01012345678, M)
        :return:
        """
        self.claim[type_] = value

    def as_jwt(self, issued: int, expiration: int) -> Jwt:
        kid = self.did + '#' + self.key_id
        header = Header(alg=self.algorithm, kid=kid)

        contents = {
            Payload.ISSUER: self.did,
            Payload.ISSUED_AT: issued,
            Payload.EXPIRATION: expiration,
            Payload.SUBJECT: self.target_did,
            Payload.CLAIM: self.claim,
            Payload.NONCE: self.nonce,
            Payload.JTI: self.jti,
            Payload.TYPE: self.get_types(),
            Payload.VERSION: self.version
        }
        payload = Payload(contents=contents)
        return Jwt(header, payload)

    @staticmethod
    def from_encoded_jwt(encoded_jwt: str) -> 'Credential':
        """Returns the credential object representation of the Jwt argument.

        :param encoded_jwt: the JWT with properties of the Credential object
        :return:
        """
        return Credential.from_jwt(Jwt.decode(encoded_jwt))

    @staticmethod
    def from_jwt(jwt: Jwt) -> 'Credential':
        """Returns the credential object representation of the String argument.

        :param jwt: encodedJwt the String returned by calling `didsdk.core.did_key_holder.sign(Jwt)`.
        :return: the credential object from jwt
        """
        payload = jwt.payload
        issuer_did = IssuerDid.from_jwt(jwt)
        return Credential(issuer_did, target_did=payload.sub, claim=payload.claim,
                          jti=payload.jti, nonce=payload.nonce, version=payload.version)

    def get_types(self) -> list:
        return [self.DEFAULT_TYPE] + list(self.claim.keys())
