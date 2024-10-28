from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.jwt.convert_jwt import ConvertJwt
from didsdk.jwt.elements import Header, Payload
from didsdk.jwt.jwt import Jwt


class IssuerDid(ConvertJwt):
    """This class holds DID-related information of the issuer in JWT.

    We can get this information from the JWT header.
    """

    # seconds
    EXP_DURATION = 5 * 60

    def __init__(self, did: str, algorithm: str, key_id: str):
        self._did: str = did
        self._algorithm: str = algorithm
        self._key_id: str = key_id

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def did(self) -> str:
        return self._did

    @property
    def duration(self) -> int:
        return self.EXP_DURATION

    @property
    def key_id(self) -> str:
        return self._key_id

    @staticmethod
    def from_did_key_holder(did_key_holder: DidKeyHolder) -> "IssuerDid":
        """Returns the IssuerDid object representation of the String argument.

        :param did_key_holder: encodedJwt the String returned by calling `didsdk.core.did_key_holder.sign(Jwt)`.
        :return: the IssuerDid object from DidKeyHolder.
        """
        return IssuerDid(did=did_key_holder.did, algorithm=did_key_holder.type.name, key_id=did_key_holder.key_id)

    @staticmethod
    def from_encoded_jwt(encoded_jwt: str) -> "IssuerDid":
        """Returns the IssuerDid object representation of the Jwt argument.

        :param encoded_jwt: the encoded jwt.
        :return: the IssuerDid object from encoded jwt.
        """
        return IssuerDid.from_jwt(Jwt.decode(encoded_jwt))

    @staticmethod
    def from_jwt(jwt: Jwt) -> "IssuerDid":
        """Returns the IssuerDid object representation of the Jwt argument.

        :param jwt: the JWT with properties of the Presentation object.
        :return: the IssuerDid object from Jwt.
        """
        kid = jwt.header.kid.split("#")
        return IssuerDid(did=kid[0], algorithm=jwt.header.alg, key_id=kid[1])

    def as_jwt(self, issued: int, expiration: int) -> Jwt:
        """Create a JWT object by this object.

        :param issued: issued time for the JWT token.
        :param expiration: expiration time for the JWT token.
        :return: a JWT token from this object.
        """
        kid = f"{self.did}#{self._key_id}"
        contents = {Payload.ISSUER: self._did, Payload.ISSUED_AT: issued, Payload.EXPIRATION: expiration}
        header = Header(alg=self._algorithm, kid=kid)
        payload = Payload(contents=contents)
        return Jwt(header, payload)
