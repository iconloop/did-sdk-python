import os
from pathlib import Path

import pytest
from coincurve import PrivateKey
from iconsdk.wallet.wallet import KeyWallet
from loguru import logger

from didsdk.core.algorithm_provider import AlgorithmProvider, AlgorithmType
from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.core.key_provider import KeyProvider
from didsdk.core.key_store import DidKeyStore
from didsdk.did_service import DidService
from didsdk.document.document import Document
from didsdk.document.encoding import EncodeType
from didsdk.exceptions import DocumentException
from didsdk.jwt.jwt import Jwt
from didsdk.score.did_score_parameter import DidScoreParameter


class TestDidService:
    KEY_FILE_NAME = "key_file_for_test.json"
    PASSWORD = "P@ssw0rd"
    FIRST_KEY_ID = "python-sdk-key"
    SECOND_KEY_ID = "2nd-key"

    @pytest.fixture
    def key_holder_from_key_store_file(self) -> DidKeyHolder:
        did_key_holder = DidKeyStore.load_did_key_holder(f"{self.KEY_FILE_NAME}", self.PASSWORD)
        logger.debug(f"did key holder: {did_key_holder}")
        return did_key_holder

    @pytest.mark.vcr
    async def test_create(self, did_service_testnet: DidService, test_wallet_keys, issuer_private_key_hex):
        # GIVEN a wallet and a key provider
        wallet = KeyWallet.load(bytes.fromhex(test_wallet_keys["private"]))
        algorithm_type = AlgorithmType.ES256K
        algorithm = AlgorithmProvider.create(algorithm_type)
        did_private_key = PrivateKey(bytes.fromhex(issuer_private_key_hex))
        key_provider = KeyProvider(self.FIRST_KEY_ID, algorithm_type, did_private_key.public_key, did_private_key)

        # GIVEN a parameter set to create DID Document
        params = DidScoreParameter.create(key_provider, EncodeType.BASE64)

        # WHEN try to create new DID Document
        document: Document = await did_service_testnet.create(wallet, params)
        logger.debug(f"did: {document.id}")

        # THEN success to get data same with above given data by the created Document object.
        key_holder = DidKeyHolder(
            did=document.id, key_id=key_provider.key_id, type=key_provider.type, private_key=key_provider.private_key
        )
        public_key_property = document.get_public_key_property(self.FIRST_KEY_ID)

        assert self.FIRST_KEY_ID == public_key_property.id
        assert key_provider.public_key.format() == public_key_property.public_key.format()
        assert algorithm.public_key_to_bytes(key_provider.public_key) == algorithm.public_key_to_bytes(
            public_key_property.public_key
        )

        # for other test
        key_file_path = Path(self.KEY_FILE_NAME)
        if key_file_path.exists():
            os.remove(key_file_path)
        DidKeyStore.store(self.KEY_FILE_NAME, self.PASSWORD, key_holder)

    @pytest.mark.vcr
    async def test_add_public_key(
        self, did_service_testnet: DidService, test_wallet_keys, key_holder_from_key_store_file: DidKeyHolder
    ):
        # GIVEN a wallet and a did key holder
        wallet = KeyWallet.load(bytes.fromhex(test_wallet_keys["private"]))

        # GIVEN a key_provider
        new_key_id = self.SECOND_KEY_ID
        algorithm = AlgorithmProvider.create(AlgorithmType.ES256K)
        key_provider = algorithm.generate_key_provider(new_key_id)

        # WHEN try to add new key
        jwt: Jwt = DidScoreParameter.add_key(key_holder_from_key_store_file, key_provider, EncodeType.BASE64)
        signed_jwt = key_holder_from_key_store_file.sign(jwt)

        document: Document = await did_service_testnet.add_public_key(wallet, signed_jwt)

        # THEN success to get new key of above the new_key_id.
        assert document.public_key.get(new_key_id)

        logger.debug(f"signed jwt: {signed_jwt}")
        logger.debug(f"document: {document}")
        logger.debug(f"document json: {document.serialize()}")

    def test_get_public_key(self, did_service_testnet: DidService, key_holder_from_key_store_file: DidKeyHolder):
        # GIVEN a key provider
        # WHEN try to get a public key
        public_key = did_service_testnet.get_public_key(key_holder_from_key_store_file.did, self.FIRST_KEY_ID)

        # THEN success to get the same public key with another public key of above the did key holder
        assert key_holder_from_key_store_file.private_key.public_key == public_key

    def test_get_version(self, did_service_testnet: DidService):
        # WHEN try to get version of did score
        version = did_service_testnet.get_version()

        # THEN success to get version of did score without any error.
        assert version
        logger.debug(f"DID SCORRE VERSION: {version}")

    def read_document(self, did_service_testnet: DidService, key_holder_from_key_store_file: DidKeyHolder):
        # GIVEN a did key holder
        # WHEN try to read the did document
        document: Document = did_service_testnet.read_document(key_holder_from_key_store_file.did)

        # THEN success to get the same data with above the did key holder
        assert document.id == key_holder_from_key_store_file.did
        assert document.public_key == key_holder_from_key_store_file.private_key.public_key

    @pytest.mark.vcr
    async def test_revoke_key(
        self, did_service_testnet: DidService, test_wallet_keys, key_holder_from_key_store_file: DidKeyHolder
    ):
        # GIVEN a did key holder, a wallet and a revoke_key_id
        wallet = KeyWallet.load(bytes.fromhex(test_wallet_keys["private"]))
        revoke_key_id = self.SECOND_KEY_ID
        jwt: Jwt = DidScoreParameter.revoke_key(key_holder_from_key_store_file, revoke_key_id)
        signed_jwt = key_holder_from_key_store_file.sign(jwt)

        # WHEN try to revoke the key
        # THEN can not find the revoke_key_id in the document.
        document: Document = did_service_testnet.read_document(key_holder_from_key_store_file.did)
        target_key = document.get_public_key_property(revoke_key_id)
        if target_key and not target_key.revoked:
            document: Document = await did_service_testnet.revoke_key(wallet, signed_jwt)
            assert document.public_key.get(revoke_key_id).revoked
        else:
            with pytest.raises(DocumentException):
                await did_service_testnet.revoke_key(wallet, signed_jwt)
