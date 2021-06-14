# TODO: remove to set a library for replace `java.security.Signature`


class KeyPair:
    pass


class KeyFactory:
    @classmethod
    def get_instance(cls, get_key_algorithm) -> 'KeyFactory':
        pass

    def generate_public_key(self, param):
        pass

    def generate_private_key(self, param):
        pass


class KeyPairGenerator:
    @classmethod
    def get_instance(cls, param, PROVIDER) -> 'KeyPairGenerator':
        pass

    def init(self, param, param1):
        pass

    def generate_key_pair(self):
        pass
