import json
from typing import List

from didsdk.document.encoding import EncodeType
from didsdk.jwt.elements import Header


class Jwe:
    def __init__(self, encoded_jwe: List[str]):
        self._encoded_token = encoded_jwe
        self.b_header = EncodeType.BASE64URL.value.decode(encoded_jwe[0])
        self.b_encrypted_key = EncodeType.BASE64URL.value.decode(encoded_jwe[1])
        self.b_iv = EncodeType.BASE64URL.value.decode(encoded_jwe[2])
        self.b_cipher_text = EncodeType.BASE64URL.value.decode(encoded_jwe[3])
        self.b_auth_tag = EncodeType.BASE64URL.value.decode(encoded_jwe[4])

        header = json.loads(self.b_header.decode('utf-8'))
        self.header = Header(**header)
