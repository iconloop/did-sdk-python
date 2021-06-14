import abc

from coincurve import PublicKey, PrivateKey

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.core.key_provider import KeyProvider
from didsdk.exceptions import AlgorithmException, KeyPairException
from didsdk.will_be_removed import KeyPair, KeyFactory


class Algorithm(abc.ABC):
    """This abstract class is used in the Signing or Verification process of a icon-DID."""
    @property
    def type(self) -> AlgorithmType:
        """Returns the type of Algorithm.

        :return: the type of algorithm.
        """
        raise NotImplementedError

    def bytes_to_public_key(self, bytes_format: bytes) -> PublicKey:
        """Convert a bytes to the PublicKey object.

        :param bytes_format:
        :return: a converted PublicKey object from bytes_format.
        """
        try:
            key_factory = KeyFactory.get_instance(self.type.key_algorithm)
            return key_factory.generate_public_key('X509EncodedKeySpec(b)')
        except Exception:
            raise KeyPairException("Can not reconstruct the public key")

    def bytes_to_private_key(self, bytes_format: bytes) -> PrivateKey:
        """Convert a bytes to the PrivateKey object.

        :param bytes_format:
        :return: a converted PrivateKey object from bytes_format.
        """
        try:
            key_factory = KeyFactory.get_instance(self.type.key_algorithm)
            return key_factory.generate_private_key('PKCS8EncodedKeySpec(b)')
        except Exception:
            raise KeyPairException("Can not reconstruct the private key")

    def generate_key_pair(self) -> KeyPair:
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
            return KeyProvider(key_id=key_id, type_=self.type, 
                               public_key=key_pair.get_public_key(), private_key=key_pair.get_private_key())
        except Exception as e:
            raise AlgorithmException(e)

    def public_key_to_bytes(self, public_key: PublicKey) -> bytes:
        """Returns a bytes in primary encoding format of the PublicKey object.

        :param public_key: a public key.
        :return: a bytes in primary encoding format of the PublicKey object.
        """
        return public_key.get_encoded()

    def private_key_to_bytes(self, private_key: PrivateKey) -> bytes:
        """Returns a bytes in primary encoding format of the PrivateKey object.

        :param private_key: a private key.
        :return: a bytes in primary encoding format of the PrivateKey object.
        """
        return private_key.get_encoded()

    def sign(self, private_key: PrivateKey, data: bytes) -> bytes:
        """Sign the given data using this Algorithm instance and the PrivateKey.

        :param private_key: A private key.
        :param data: an array of bytes representing the base64 encoded content to be verified against the signature.
        :return: the signature for data by the private key.
        """
        raise NotImplementedError

    def sign_with_signature(self, algorithm: str, private_key: PrivateKey, data: bytes) -> bytes:
        """Sign the given data using the Signature instance and the privateKey.
        
        :param algorithm: the name of algorithm.
        :param private_key: a private key for signing.
        :param data: a bytes representing the base64 encoded content to be verified against the signature.
        :return: a signature for data
        """
        # try:
        #     signature = Signature.get_instance(algorithm)
        #     signature.init_sign(private_key)
        #     signature.update(data)
        #     return signature.sign()
        # except Exception as e:
        #     raise AlgorithmException(e)
        raise NotImplementedError
        
    def verify(self, public_key: PublicKey, data: bytes, signature: bytes) -> bool:
        """Verify the given token using this Algorithm instance.

        :param public_key: a public key to verify for data.
        :param data: the array of bytes used for signing
        :param signature: a signature for data.
        :return: if the signature is valid, return true, or return false
        """
        raise NotImplementedError

    def verify_with_signature(self, algorithm: str, public_key: PublicKey, data: bytes, signature: bytes) -> bool:
        """Verify the given token using the Signature instance.

        :param algorithm: the name of algorithm.
        :param public_key: a public key to use in the verify.
        :param data: a bytes used for signing.
        :param signature: a signature for data.
        :return: if the signature is valid, return true, or return false.
        """
        # try:
        #     new_signature = Signature.get_instance(algorithm)
        #     new_signature.init_verify(public_key)
        #     new_signature.update(data)
        #     return new_signature.verify(signature)
        # except Exception as e:
        #     raise AlgorithmException(e)
        raise NotImplementedError
