from dataclasses import dataclass


@dataclass(frozen=True)
class AuthenticationProperty:
    """This corresponds to the authentication property of the DIDs specification.

    https://w3c-ccg.github.io/did-spec/#authentication
    """

    type: str
    public_key: str
