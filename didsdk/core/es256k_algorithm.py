from coincurve import PublicKey, PrivateKey

from didsdk.core.algorithm import Algorithm
from didsdk.core.algorithm_provider import AlgorithmType, AlgorithmProvider
from didsdk.will_be_removed import KeyPair, KeyPairGenerator


class ES256KAlgorithm(Algorithm):
    def __init__(self):
        self._type = AlgorithmType.ES256K
        # TODO: check how to set spec
        self._spec = 'ECNamedCurveTable.getParameterSpec("secp256k1")'
        self._ec_parameter_spec = 'ECParameterSpec(this.spec.getCurve(), this.spec.getG(), this.spec.getN())'

    @property
    def type(self) -> AlgorithmType:
        return self._type

    def bytes_to_public_key(self, bytes_format: bytes) -> PublicKey:
        return PublicKey(bytes_format)

    def bytes_to_private_key(self, bytes_format: bytes) -> PrivateKey:
        return PrivateKey(bytes_format)

    def generate_key_pair(self) -> KeyPair:
        key_generator = KeyPairGenerator.get_instance("EC", AlgorithmProvider.PROVIDER)
        key_generator.init('new ECGenParameterSpec(EC_CURVE_PARAM_SECP256K1)', AlgorithmProvider.SECURE_RANDOM)
        return key_generator.generate_key_pair()

    def public_key_to_bytes(self, public_key: PublicKey):
        return public_key.format(True)

    def private_key_to_bytes(self, private_key: PrivateKey):
        return private_key.to_pem()

    def sign(self, private_key: PrivateKey, data: bytes) -> bytes:
        return private_key.sign_recoverable(data)

    def verify(self, public_key: PublicKey, data: bytes, signature: bytes) -> bool:
        try:
            return public_key.verify(signature, data)
        except Exception:
            return False
