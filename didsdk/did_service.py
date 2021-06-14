import asyncio
import json

from iconsdk.icon_service import IconService
from iconsdk.signed_transaction import SignedTransaction, Transaction
from iconsdk.wallet.wallet import KeyWallet, Wallet

from didsdk.document.converters import Converters
from didsdk.document.document import Document
from didsdk.exceptions import TransactionException, ResolveException
from didsdk.jwt.jwt import Jwt
from didsdk.score.did_score import DidScore


class DidService:
    """This class use to enable the full functionality of DID Documents on a icon blockchain network.
    In order to create and update DID Documents, a transaction is required and this class uses IconService.
    @see `iconsdk.icon_service.IconService`
    https://github.com/icon-project/icon-sdk-python"""

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

    def _get_did(self, event_log: list, event_name: str) -> str:
        """Get the id of document from the transaction event.

        :param event_log: the EventLog object
        :param event_name: the name of score event
        :return: the id of document
        """
        for log in event_log:
            items = log['eventLogs']
            if items[0] == event_name:
                return items[2]
        return None

    def _send_jwt(self, wallet: KeyWallet, signed_jwt: str, method: str) -> dict:
        """Sends a transaction with a json web token string.

        :param wallet: the wallet for transaction
        :param signed_jwt: the string that signed the object returned from `ScoreParameter`.
        :param method: the name of score function
        :return: the TransactionResult object
        """
        if not Jwt.decode().get_signature():
            raise Exception('JWT string must contain signature to send a transaction.')

        transaction = self._did_score.jwtMethod(wallet.get_address(), signed_jwt, method)
        tx_hash = self._send_transaction(transaction, wallet)

        loop = asyncio.get_event_loop()
        coroutine = asyncio.wait_for(self._get_transaction_result(tx_hash), timeout=self._timeout)
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, loop)
            tx_result = future.result()
        except asyncio.TimeoutError:
            raise TransactionException('Timeout')

        return tx_result

    async def _get_transaction_result(self, tx_hash: str) -> dict:
        """Get the transaction result that matches the hash of transaction.
        This method calls `iconsdk.icon_service.IconService.get_transaction_result` every 1 second
        until the transaction is confirmed.

        :param tx_hash:
        :return:
        """
        try:
            response = None
            tx_result = None
            while response is None:
                await asyncio.sleep(1)
                tx_result = self._iconservice.get_transaction_result(tx_hash)
                if tx_result.get('status') == 0:
                    raise TransactionException(tx_result)
            return tx_result
        except Exception as e:
            raise TransactionException(e)

    def _send_transaction(self, transaction: Transaction, wallet: Wallet) -> str:
        """Sends a transaction.

        :param transaction: the Transaction object.
        :param wallet: the wallet for transaction.
        :return: the hash of transaction.
        """
        signed_tx = SignedTransaction(transaction, wallet)
        return self._iconservice.send_transaction(signed_tx)

    def add_public_key(self, wallet: KeyWallet, signed_jwt: str) -> Document:
        """Add a publicKey to DID Document.

        :param wallet: the wallet for transaction.
        :param signed_jwt: the string that signed the object returned.
        :return: the Document object.
        """
        tx_result = self._send_jwt(wallet, signed_jwt, method='update')
        did = self._get_did(tx_result['eventLogs'], event_name='AddKey(Address,str,str)')
        return self.read_document(did)

    def create(self, wallet: KeyWallet, public_key: str) -> Document:
        """Create a DID Document.

        :param wallet: the wallet for transaction
        :param public_key: the json string returned by calling
        :return: the Document object
        """
        try:
            json.loads(public_key)
        except Exception as e:
            raise TypeError('Invalid type of public key.')

        transaction = self._did_score.create(from_address=wallet.get_address(), public_key=public_key)
        tx_hash = self._send_transaction(transaction, wallet)

        loop = asyncio.get_event_loop()
        coroutine = asyncio.wait_for(self._get_transaction_result(tx_hash), timeout=self._timeout)
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, loop)
            tx_result = future.result()
        except asyncio.TimeoutError:
            raise TransactionException('Timeout')

        did = self._get_did(tx_result['eventLogs'], 'Create(Address,str,str)')
        return self.read_document(did)

    def get_did(self, address: str) -> str:
        """Get the id of document from the did score.

        :param address: the address of wallet is used for transaction.
        :return: the id of document.
        """
        return self._did_score.get_did(address)

    def get_public_key(self, did: str, key_id: str) -> 'PublickKey':
        """Get a publicKey that matches the id of DID document and the id of publicKey.

        :param did: the id of DID document
        :param key_id: the id of publicKey
        :return: the publicKey object
        """
        document = self.read_document(did)
        public_key_property = document.get_public_key_property(key_id)
        return public_key_property.public_key

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
            raise Exception('did cannot be None.')

        json_data = self._did_score.get_did_document(did)
        try:
            return Converters.deserialize(json_data, Document)
        except Exception:
            raise ResolveException(f"'{json_data}' parsing error.")

    def revoke_key(self, wallet: 'KeyWallet', signed_jwt: str) -> Document:
        """Revoke a publicKey in the DID Document.

        :param wallet: the wallet for transaction.
        :param signed_jwt: the string that signed the object returned.
        :return: the Document object
        """
        tx_result = self._send_jwt(wallet, signed_jwt, method='update')
        did = self._get_did(tx_result['eventLogs'], event_name='RevokeKey(Address,str,str)')
        return self.read_document(did)
