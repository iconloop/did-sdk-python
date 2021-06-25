import abc

from didsdk.jwt.jwt import Jwt


class ConvertJwt(abc.ABC):
    """A interface to convert `Credential` and `Presentation to 'Json Web Token'"""

    @property
    def duration(self) -> int:
        """The time in seconds from the issued time to expiration.

        :return: the duration in seconds.
        """
        raise NotImplementedError

    def as_jwt(self, issued: int, expiration: int):
        raise NotImplementedError

    @staticmethod
    def from_encoded_jwt(encoded_jwt: str) -> 'Presentation':
        raise NotImplementedError

    @staticmethod
    def from_jwt(jwt: Jwt) -> 'Presentation':
        raise NotImplementedError
