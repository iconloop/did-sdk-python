import abc


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
