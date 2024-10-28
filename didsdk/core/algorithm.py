import abc
from typing import TYPE_CHECKING

from coincurve import PrivateKey, PublicKey

from didsdk.core.key_provider import KeyProvider
from didsdk.exceptions import AlgorithmException

if TYPE_CHECKING:
    from didsdk.core.algorithm_provider import AlgorithmType


class Algorithm(abc.ABC):
    """This abstract class is used in the Signing or Verification process of a icon-DID."""

    @property
    def type(self) -> "AlgorithmType":
        """Returns the type of Algorithm.

        :return: the type of algorithm.
        """
        raise NotImplementedError

    def bytes_to_public_key(self, bytes_format: bytes) -> PublicKey:
        """Convert a bytes to the PublicKey object.

        :param bytes_format: a public key by type of bytes
        :return: a converted PublicKey object from bytes_format.
        """
        raise NotImplementedError

    def bytes_to_private_key(self, bytes_format: bytes) -> PrivateKey:
        """Convert a bytes to the PrivateKey object.

        :param bytes_format: a private key by type of bytes
        :return: a converted PrivateKey object from bytes_format.
        """
        raise NotImplementedError

    def generate_key_pair(self):
        raise NotImplementedError

    def generate_key_provider(self, key_id: str) -> KeyProvider:
        """Create a KeyProvider object.

        This will generate a new public/private key every time it is called.
        And return the id of key, the type of this algorithm instance and the new public/private key.

        :param key_id: the id of the key to use in the DID document.
        :return: the KeyProvider object.
        """
        try:
            key_pair = self.generate_key_pair()
            return KeyProvider(key_id, self.type, key_pair.public_key, key_pair.private_key)
        except Exception as e:
            raise AlgorithmException(e)

    def public_key_to_bytes(self, public_key: PublicKey) -> bytes:
        """Returns a bytes in primary encoding format of the PublicKey object.

        :param public_key: a public key.
        :return: a bytes in primary encoding format of the PublicKey object.
        """
        raise NotImplementedError

    def private_key_to_bytes(self, private_key: PrivateKey) -> bytes:
        """Returns a bytes in primary encoding format of the PrivateKey object.

        :param private_key: a private key.
        :return: a bytes in primary encoding format of the PrivateKey object.
        """
        raise NotImplementedError

    def sign(self, private_key: PrivateKey, data: bytes) -> bytes:
        """Sign the given data using this Algorithm instance and the PrivateKey.

        :param private_key: A private key.
        :param data: an array of bytes representing the base64 encoded content to be verified against the signature.
        :return: the signature for data by the private key.
        """
        raise NotImplementedError

    def verify(self, public_key: PublicKey, data: bytes, signature: bytes) -> bool:
        """Verify the given token using this Algorithm instance.

        :param public_key: a public key to verify for data.
        :param data: the array of bytes used for signing
        :param signature: a signature for data.
        :return: if the signature is valid, return true, or return false
        """
        raise NotImplementedError
