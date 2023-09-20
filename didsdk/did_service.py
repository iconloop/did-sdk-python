import asyncio
import json
from typing import Union

from coincurve import PublicKey
from iconsdk.exception import JSONRPCException
from iconsdk.icon_service import IconService
from iconsdk.signed_transaction import SignedTransaction, Transaction
from iconsdk.wallet.wallet import KeyWallet, Wallet
from loguru import logger

from didsdk import settings
from didsdk.document.document import Document
from didsdk.exceptions import DocumentException, ResolveException, TransactionException
from didsdk.jwt.jwt import Jwt
from didsdk.score.did_score import DidScore


class DidService:
    """This class use to enable the full functionality of DID Documents on a icon blockchain network.

    In order to create and update DID Documents,
    a transaction is required and this class uses `iconsdk.icon_service.IconService`.
    https://github.com/icon-project/icon-sdk-python
    """

    def __init__(self, iconservice: IconService, network_id: int, score_address: str, timeout: int = 15_000):
        """Create the instance.

        :param iconservice: the IconService object.
        :param network_id: the network ID of the blockchain.
        :param score_address: the did score address deployed to the blockchain.
        :param timeout: the specified timeout, in milliseconds.
        """
        self._iconservice: IconService = iconservice
        self._network_id: int = network_id
        self._did_score: DidScore = DidScore(self._iconservice, self._network_id, score_address)
        self._timeout: int = timeout

    def _get_did(self, event_log: list, event_name: str) -> Union[str, None]:
        """Get the id of document from the transaction event.

        :param event_log: the EventLog object
        :param event_name: the name of score event
        :return: the id of document
        """
        for log in event_log:
            items = log["indexed"]
            if items[0] == event_name:
                return items[2]
        return None

    async def _get_transaction_result(self, tx_hash: str) -> dict:
        """Get the transaction result that matches the hash of transaction.

        This method calls `iconsdk.icon_service.IconService.get_transaction_result` every 1 second
        until the transaction is confirmed.

        :param tx_hash:
        :return:
        """
        response = None
        retry_times = settings.DIDSDK_TX_RETRY_COUNT
        while response is None and retry_times > 0:
            try:
                tx_result = self._iconservice.get_transaction_result(tx_hash)
                if not tx_result:
                    raise JSONRPCException("transaction result is None.")
            except JSONRPCException as e:
                logger.debug(f"{e}")

                if retry_times == 0:
                    raise TransactionException(e)

                retry_times -= 1
                logger.debug(f"Remain to retry request for getting transaction result: {retry_times}")

                await asyncio.sleep(settings.DIDSDK_TX_SLEEP_TIME)
                continue

            return tx_result

    async def _send_jwt(self, wallet: KeyWallet, signed_jwt: str, method: str) -> dict:
        """Sends a transaction with a json web token string.

        :param wallet: the wallet for transaction
        :param signed_jwt: the string that signed the object returned from `ScoreParameter`.
        :param method: the name of score function
        :return: the TransactionResult object
        """
        if not Jwt.decode(signed_jwt).signature:
            raise Exception("JWT string must contain signature to send a transaction.")

        transaction = self._did_score.jwt_method(from_address=wallet.get_address(), jwt=signed_jwt, method=method)
        tx_hash = self._send_transaction(transaction, wallet)

        return await self._get_transaction_result(tx_hash)

    def _send_transaction(self, transaction: Transaction, wallet: Wallet) -> str:
        """Sends a transaction.

        :param transaction: the Transaction object.
        :param wallet: the wallet for transaction.
        :return: the hash of transaction.
        """
        signed_tx = SignedTransaction(transaction, wallet)
        return self._iconservice.send_transaction(signed_tx)

    async def add_public_key(self, wallet: KeyWallet, signed_jwt: str) -> Document:
        """Add a publicKey to DID Document.

        :param wallet: the wallet for transaction.
        :param signed_jwt: the string that signed the object returned.
        :return: the Document object.
        """
        tx_result = await self._send_jwt(wallet, signed_jwt, method="update")
        did = self._get_did(tx_result["eventLogs"], event_name="AddKey(Address,str,str)")
        if not did:
            raise DocumentException(tx_result["failure"]["message"])

        return self.read_document(did)

    async def create(self, wallet: KeyWallet, public_key: str) -> Document:
        """Create a DID Document.

        :param wallet: the wallet for transaction
        :param public_key: the json string returned by calling
        :return: the Document object
        """
        try:
            json.loads(public_key)
        except Exception as e:
            raise TypeError(f"Invalid type of public key.({e})")

        transaction = self._did_score.create(from_address=wallet.get_address(), public_key=public_key)
        tx_hash = self._send_transaction(transaction, wallet)
        tx_result = await asyncio.wait_for(self._get_transaction_result(tx_hash), timeout=self._timeout)
        did = self._get_did(tx_result["eventLogs"], "Create(Address,str,str)")
        if not did:
            raise DocumentException(tx_result["failure"]["message"])

        return self.read_document(did)

    def get_public_key(self, did: str, key_id: str) -> PublicKey:
        """Get a publicKey that matches the id of DID document and the id of publicKey.

        :param did: the id of DID document
        :param key_id: the id of publicKey
        :return: the publicKey object
        """
        document = self.read_document(did)
        public_key_property = document.get_public_key_property(key_id)
        return public_key_property.public_key if public_key_property else public_key_property

    def get_version(self) -> str:
        """Get the version of score.

        :return: the version of score.
        """
        return self._did_score.get_version()

    def read_document(self, did: str) -> Document:
        """Get a DID Document.

        :param did: the id of a DID Document
        :return: the Document object
        """
        if not did:
            raise Exception("did cannot be None.")

        json_data = self._did_score.get_did_document(did)
        try:
            return Document.deserialize(json_data)
        except Exception:
            raise ResolveException(f"'{json_data}' parsing error.")

    async def revoke_key(self, wallet: "KeyWallet", signed_jwt: str) -> Document:
        """Revoke a publicKey in the DID Document.

        :param wallet: the wallet for transaction.
        :param signed_jwt: the string that signed the object returned.
        :return: the Document object
        """
        tx_result = await self._send_jwt(wallet, signed_jwt, method="update")
        did = self._get_did(tx_result["eventLogs"], event_name="RevokeKey(Address,str,str)")
        if not did:
            raise DocumentException(tx_result["failure"]["message"])

        return self.read_document(did)
