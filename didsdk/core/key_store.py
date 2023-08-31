import json
import uuid
from dataclasses import dataclass

from coincurve import PrivateKey
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util import Counter
from eth_keyfile import decode_keyfile_json, load_keyfile
from eth_utils import (
    big_endian_to_int,
    encode_hex,
    int_to_big_endian,
    keccak,
    remove_0x_prefix,
)
from iconsdk.utils import store_keystore_file_on_the_path
from iconsdk.utils.validation import has_keys
from loguru import logger

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.exceptions import KeyStoreException

CURRENT_VERSION = 3
N_STANDARD = 1 << 14
P_STANDARD = 1
R = 8
DKLEN = 32
CIPHER = "aes-128-ctr"
KDF = "scrypt"


def _create_v3_keyfile_json(private_key, password, kdf=None, work_factor=None):
    kdf = kdf if kdf else KDF
    work_factor = work_factor if work_factor else N_STANDARD
    salt = Random.get_random_bytes(16)

    if kdf == KDF:
        derived_key = _scrypt_hash(
            password,
            salt=salt,
            buflen=DKLEN,
            r=R,
            p=P_STANDARD,
            n=work_factor,
        )
        kdfparams = {
            "dklen": DKLEN,
            "n": work_factor,
            "r": R,
            "p": P_STANDARD,
            "salt": encode_hex_no_prefix(salt),
        }
    else:
        raise NotImplementedError("KDF not implemented: {0}".format(kdf))

    iv = big_endian_to_int(Random.get_random_bytes(16))
    encrypt_key = derived_key[:16]
    ciphertext = encrypt_aes_ctr(private_key, encrypt_key, iv)
    mac = keccak(derived_key[16:32] + ciphertext)

    return {
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": encode_hex_no_prefix(int_to_big_endian(iv)),
            },
            "ciphertext": encode_hex_no_prefix(ciphertext),
            "kdf": kdf,
            "kdfparams": kdfparams,
            "mac": encode_hex_no_prefix(mac),
        },
        "id": str(uuid.uuid4()),
        "version": CURRENT_VERSION,
    }


def _scrypt_hash(password, salt, n, r, p, buflen):
    derived_key = scrypt(
        password,
        salt=salt,
        key_len=buflen,
        N=n,
        r=r,
        p=p,
        num_keys=1,
    )
    return derived_key


def encrypt_aes_ctr(value, key, iv):
    ctr = Counter.new(128, initial_value=iv, allow_wraparound=True)
    encryptor = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = encryptor.encrypt(value)
    return ciphertext


def encode_hex_no_prefix(value):
    return remove_0x_prefix(encode_hex(value))


def is_did_keystore_file(keystore: dict) -> bool:
    """Checks data in a keystore file is valid.

    :return: type(bool)
        True: When format of the keystore is valid.
        False: When format of the keystore is invalid.
    """
    root_keys = ["version", "id", "did", "crypto", "keyId", "type"]
    crypto_keys = ["ciphertext", "cipherparams", "cipher", "kdf", "kdfparams", "mac"]
    crypto_cipherparams_keys = ["iv"]

    is_valid = (
        has_keys(keystore, root_keys)
        and has_keys(keystore["crypto"], crypto_keys)
        and has_keys(keystore["crypto"]["cipherparams"], crypto_cipherparams_keys)
    )

    if is_valid:
        return is_valid

    raise KeyStoreException("The keystore file is invalid for ICON DID.")


@dataclass
class Crypto:
    cipher: str
    ciphertext: str
    cipherparams: dict
    kdf: str
    kdfparams: dict
    mac: str


@dataclass(frozen=True)
class DidKeyStoreFile:
    did: str
    keyId: str
    type: str
    crypto: Crypto
    id: str
    version: int

    @property
    def kid(self):
        return self.did + "#" + self.keyId


class DidKeyStore:
    @staticmethod
    def load_did_key_holder(file_path: str, password: str) -> DidKeyHolder:
        """Loads a DidKeyHolder object from a keystore file with your password.

        :param file_path: File path of the keystore file. type(str)
        :param password:
            Password for the keystore file.
            It must include alphabet character, number, and special character.
        :return: An instance of DidKeyHolder class.
        """
        try:
            with open(file_path, "rb") as file:
                keyfile_json = load_keyfile(file)
                private_key: bytes = decode_keyfile_json(keyfile_json, bytes(password, "utf-8"))
                return DidKeyHolder(
                    did=keyfile_json["did"],
                    key_id=keyfile_json["keyId"],
                    type=AlgorithmType[keyfile_json["type"]],
                    private_key=PrivateKey(private_key),
                )
        except FileNotFoundError as e:
            raise KeyStoreException(f"File not found: {e}")
        except ValueError as e:
            raise KeyStoreException(f"Wrong password: {e}")
        except Exception as e:
            raise KeyStoreException(f"Keystore error: {e}")

    @staticmethod
    def store(file_path: str, password: str, key_holder: DidKeyHolder):
        """Stores data of an instance of a derived DidKeyHolder class on the file path with your password.

        :param file_path: File path of the keystore file. type(str)
        :param password:
            Password for the keystore file. Password must include alphabet character, number, and special character.
            type(str)
        :param key_holder: A DidKeyHolder object for key store file.
        """
        key_store_contents = key_holder.to_dict(password)

        try:
            if is_did_keystore_file(key_store_contents):
                json_string_keystore_data = json.dumps(key_store_contents)
                store_keystore_file_on_the_path(file_path, json_string_keystore_data)
                logger.info(f"Stored Key. DID: {key_holder.did}, File path: {file_path}")
        except FileExistsError:
            raise KeyStoreException("File already exists.")
        except PermissionError:
            raise KeyStoreException("Not enough permission.")
        except FileNotFoundError:
            raise KeyStoreException("File not found.")
        except IsADirectoryError:
            raise KeyStoreException("Directory is invalid.")
