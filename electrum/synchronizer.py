#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import asyncio
import hashlib
import binascii
from threading import Lock
from typing import Dict, List, TYPE_CHECKING, Tuple
from collections import defaultdict
import logging

from aiorpcx import TaskGroup, run_in_thread, RPCError

from .transaction import Transaction
from .util import bh2u, make_aiohttp_session, NetworkJobOnDefaultServer
from .bitcoin import address_to_scripthash, is_address, hash160_to_p2pkh
from .network import UntrustedServerReturnedError
from .logging import Logger
from .interface import GracefulDisconnect

if TYPE_CHECKING:
    from .network import Network
    from .address_synchronizer import AddressSynchronizer


class SynchronizerFailure(Exception): pass


def history_status(h):
    if not h:
        return None
    status = ''
    for tx_hash, height in h:
        status += tx_hash + ':%d:' % height
    return bh2u(hashlib.sha256(status.encode('ascii')).digest())


class SynchronizerBase(NetworkJobOnDefaultServer):
    """Subscribe over the network to a set of addresses, and monitor their statuses.
    Every time a status changes, run a coroutine provided by the subclass.
    """
    def __init__(self, network: 'Network'):
        self.asyncio_loop = network.asyncio_loop
        NetworkJobOnDefaultServer.__init__(self, network)
        self._reset_request_counters()

    def _reset(self):
        super()._reset()
        self.requested_addrs = set()
        self.scripthash_to_address = {}
        self._processed_some_notifications = False  # so that we don't miss them
        self._reset_request_counters()
        # Queues
        self.add_queue = asyncio.Queue()
        self.status_queue = asyncio.Queue()

    async def _start_tasks(self):
        try:
            async with self.group as group:
                await group.spawn(self.send_subscriptions())
                await group.spawn(self.handle_status())
                await group.spawn(self.main())
        finally:
            # we are being cancelled now
            self.session.unsubscribe(self.status_queue)

    def _reset_request_counters(self):
        self._requests_sent = 0
        self._requests_answered = 0

    def add(self, addr):
        asyncio.run_coroutine_threadsafe(self._add_address(addr), self.asyncio_loop)

    async def _add_address(self, addr: str):
        if not is_address(addr): raise ValueError(f"invalid bitcoin address {addr}")
        if addr in self.requested_addrs: return
        self.requested_addrs.add(addr)
        await self.add_queue.put(addr)

    async def _on_address_status(self, addr, status):
        """Handle the change of the status of an address."""
        raise NotImplementedError()  # implemented by subclasses

    async def send_subscriptions(self):
        async def subscribe_to_address(addr):
            h = address_to_scripthash(addr)
            self.scripthash_to_address[h] = addr
            self._requests_sent += 1
            try:
                await self.session.subscribe('blockchain.scripthash.subscribe', [h], self.status_queue)
            except RPCError as e:
                if e.message == 'history too large':  # no unique error code
                    raise GracefulDisconnect(e, log_level=logging.ERROR) from e
                raise
            self._requests_answered += 1
            self.requested_addrs.remove(addr)

        while True:
            addr = await self.add_queue.get()
            await self.group.spawn(subscribe_to_address, addr)

    async def handle_status(self):
        while True:
            h, status = await self.status_queue.get()
            addr = self.scripthash_to_address[h]
            await self.group.spawn(self._on_address_status, addr, status)
            self._processed_some_notifications = True

    def num_requests_sent_and_answered(self) -> Tuple[int, int]:
        return self._requests_sent, self._requests_answered

    async def main(self):
        raise NotImplementedError()  # implemented by subclasses


class Synchronizer(SynchronizerBase):
    '''The synchronizer keeps the wallet up-to-date with its set of
    addresses and their transactions.  It subscribes over the network
    to wallet addresses, gets the wallet to generate new addresses
    when necessary, requests the transaction history of any addresses
    we don't have the full history of, and requests binary transaction
    data of any transactions the wallet doesn't have.
    '''
    def __init__(self, wallet: 'AddressSynchronizer'):
        self.wallet = wallet
        SynchronizerBase.__init__(self, wallet.network)

    def _reset(self):
        super()._reset()
        self.new_addresses = set()
        self.new_tokens = set()
        self.requested_tx = {}
        self.requested_histories = set()
	# VIPSTARCOIN (by Qtum)
        self.requested_tx_receipt = {}
        self.requested_token_histories = {}
        self.requested_token_txs = {}

        self.lock = Lock()

    def diagnostic_name(self):
        return self.wallet.diagnostic_name()

    def is_up_to_date(self):
        return (not self.requested_addrs
                and not self.requested_histories
                and not self.requested_tx
                and not self.requested_tx_receipt
                and not self.requested_token_histories
                and not self.requested_token_txs)

    def add(self, address):
        '''This can be called from the proxy or GUI threads.'''
        with self.lock:
            self.new_addresses.add(address)

    def subscribe_to_addresses(self, addresses):
        if addresses:
            self.requested_addrs |= addresses
            self.network.subscribe_to_addresses(addresses, self.on_address_status)

    def get_status(self, h):
        if not h:
            return None
        status = ''
        for tx_hash, height in h:
            status += tx_hash + ':%d:' % height
        return bh2u(hashlib.sha256(status.encode('ascii')).digest())

    async def _on_address_status(self, addr, status):
        history = self.wallet.db.get_addr_history(addr)
        if history_status(history) == status:
            return
        if (addr, status) in self.requested_histories:
            return
        # request address history
        self.requested_histories.add((addr, status))
        h = address_to_scripthash(addr)
        self._requests_sent += 1
        result = await self.network.get_history_for_scripthash(h)
        self._requests_answered += 1
        self.logger.info(f"receiving history {addr} {len(result)}")
        hashes = set(map(lambda item: item['tx_hash'], result))
        hist = list(map(lambda item: (item['tx_hash'], item['height']), result))
        # tx_fees
        tx_fees = [(item['tx_hash'], item.get('fee')) for item in result]
        tx_fees = dict(filter(lambda x:x[1] is not None, tx_fees))
        # Check that txids are unique
        if len(hashes) != len(result):
            self.logger.info(f"error: server history has non-unique txids: {addr}")
        # Check that the status corresponds to what was announced
        elif history_status(hist) != status:
            self.logger.info(f"error: status mismatch: {addr}")
        else:
            # Store received history
            self.wallet.receive_history_callback(addr, hist, tx_fees)
            # Request transactions we don't have
            await self._request_missing_txs(hist)

        # Remove request; this allows up_to_date to be True
        self.requested_histories.discard((addr, status))

    async def _request_missing_txs(self, hist, *, allow_server_not_finding_tx=False):
        # "hist" is a list of [tx_hash, tx_height] lists
        transaction_hashes = []
        for tx_hash, tx_height in hist:
            if tx_hash in self.requested_tx:
                continue
            if self.wallet.db.get_transaction(tx_hash):
                continue
            transaction_hashes.append(tx_hash)
            self.requested_tx[tx_hash] = tx_height

        if not transaction_hashes: return
        async with TaskGroup() as group:
            for tx_hash in transaction_hashes:
                await group.spawn(self._get_transaction(tx_hash, allow_server_not_finding_tx=allow_server_not_finding_tx))

    def add_token(self, token):
        with self.lock:
            self.new_tokens.add(token)

    async def subscribe_tokens(self, tokens):
        """
        :type tokens: set(Token)
        """
        if tokens:
            await self.network.subscribe_tokens(tokens, self.on_token_status)

    async def get_token_status(self, h):
        if not h:
            return None
        status = ':'.join(['{}:{:d}:{:d}'.format(tx_hash, height, log_index)
                           for tx_hash, height, log_index in h])
        return bh2u(hashlib.sha256(status.encode('ascii')).digest())

    async def on_token_status(self, response):
        if self.wallet.synchronizer is None and self.initialized:
            return  # we have been killed, this was just an orphan callback
        params, result = self.parse_response(response)
        if not params:
            print('on_token_status err', response)
            return
        try:
            bind_addr = hash160_to_p2pkh(binascii.a2b_hex(params[0]))
            contract_addr = params[1]
            key = '{}_{}'.format(contract_addr, bind_addr)
            token = self.wallet.tokens[key]
            if token:
                token_history = self.wallet.token_history.get(key, [])
                if self.get_token_status(token_history) != result:
                    self.requested_token_histories[key] = result
                    self.network.request_token_history(token, self.on_token_history)
                    self.get_token_balance(token)
                else:
                    self.print_error('token status matched')
        except (BaseException,) as e:
            import traceback, sys
            traceback.print_exc(file=sys.stderr)
            print('on_token_status err', e)

    async def on_token_history(self, response):
        if self.wallet.synchronizer is None and self.initialized:
            return  # we have been killed, this was just an orphan callback
        params, result = self.parse_response(response)
        if not params:
            print('on_token_history err', response)
            return
        try:
            bind_addr = hash160_to_p2pkh(binascii.a2b_hex(params[0]))
            contract_addr = params[1]
            key = '{}_{}'.format(contract_addr, bind_addr)
            server_status = self.requested_token_histories.get(key)
            if server_status is None:
                self.print_error("receiving history (unsolicited)", key, len(result))
                return

            self.print_error("receiving token history", key, len(result))

            hist = list(map(lambda item: (item['tx_hash'], item['height'], item['log_index']), result))
            hashes = set(map(lambda item: (item['tx_hash'], item['log_index']), result))
            # Note if the server hasn't been patched to sort the items properly
            if hist != sorted(hist, key=lambda x: x[1]):
                self.network.interface.print_error("serving improperly sorted address histories")

            # Check that txids are unique
            if len(hashes) != len(result):
                print("error: server token history has non-unique txid_logindexs: %s" % key)
            # Check that the status corresponds to what was announced
            elif self.get_token_status(hist) != server_status:
                print("error: status mismatch: %s" % key)
            else:
                # Store received history
                self.wallet.receive_token_history_callback(key, hist)
                # Request token tx and receipts we don't have
                self.request_missing_tx_receipts(hist)
                self.request_missing_token_txs(hist)
            # Remove request; this allows up_to_date to be True
            self.requested_token_histories.pop(key)

        except (BaseException,) as e:
            print('on_token_history err', e)

    async def request_missing_tx_receipts(self, hist):
        # "hist" is a list of [tx_hash, tx_height, log_index] lists
        tx_hashs = []
        for tx_hash, tx_height, log_index in hist:
            if tx_hash in self.requested_tx_receipt:
                continue
            if tx_hash in self.wallet.tx_receipt:
                continue
            tx_hashs.append(tx_hash)
            self.requested_tx_receipt[tx_hash] = tx_height

        self.network.get_transactions_receipt(tx_hashs, self.on_tx_receipt_response)

    async def on_tx_receipt_response(self, response):
        if self.wallet.synchronizer is None and self.initialized:
            return  # we have been killed, this was just an orphan callback
        params, receipt = self.parse_response(response)
        if not params:
            print('tx_receipt_response err', response)
            return
        tx_hash = params[0]
        if not isinstance(receipt, list):
            self.print_msg("transaction receipt not list, skipping", tx_hash)
            return
        height = self.requested_tx_receipt.pop(tx_hash)
        self.wallet.receive_tx_receipt_callback(tx_hash, receipt)
        self.print_error("received tx_receipt %s height: %d" %
                         (tx_hash, height))
        # callbacks
        self.network.trigger_callback('new_tx_receipt', receipt)
        if not self.requested_tx_receipt and not self.requested_token_txs:
            self.network.trigger_callback('on_token')

    async def request_missing_token_txs(self, hist):
        # "hist" is a list of [tx_hash, tx_height, log_index] lists
        tx_hashs = []
        for tx_hash, tx_height, log_index in hist:
            if tx_hash in self.requested_token_txs:
                continue
            if tx_hash in self.wallet.token_txs:
                continue
            tx_hashs.append(tx_hash)
            self.requested_token_txs[tx_hash] = tx_height
        self.network.get_transactions(tx_hashs, self.on_token_tx_response)

    async def on_token_tx_response(self, response):
        if self.wallet.synchronizer is None and self.initialized:
            return  # we have been killed, this was just an orphan callback
        params, result = self.parse_response(response)
        if not params:
            return
        tx_hash = params[0]
        tx = Transaction(result)
        try:
            tx.deserialize()
        except Exception:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return
        tx_height = self.requested_token_txs.pop(tx_hash)
        self.wallet.receive_token_tx_callback(tx_hash, tx, tx_height)
        self.print_error("received tx %s height: %d bytes: %d" %
                         (tx_hash, tx_height, len(tx.raw)))
        # callbacks
        self.network.trigger_callback('new_token_transaction', tx)
        if not self.requested_token_txs and not self.requested_tx_receipt:
            self.network.trigger_callback('on_token')

    async def get_token_balance(self, token):
        """
        :type token: Token
        """
        await self.network.request_token_balance(token)

    async def on_token_balance_response(self, response):
        params, result = self.parse_response(response)
        if not params:
            return
        try:
            contract_addr = params[0]
            bind_addr = hash160_to_p2pkh(binascii.a2b_hex(params[1][-40:]))
            key = '{}_{}'.format(contract_addr, bind_addr)
            token = self.wallet.tokens[key]
            if token and token.balance != result and isinstance(result, int):
                token = token._replace(balance=result)
                self.wallet.tokens[key] = token
        except (BaseException,) as e:
            print('token_balance_response err', e)

    async def _get_transaction(self, tx_hash, *, allow_server_not_finding_tx=False):
        self._requests_sent += 1
        try:
            result = await self.network.get_transaction(tx_hash)
        except UntrustedServerReturnedError as e:
            # most likely, "No such mempool or blockchain transaction"
            if allow_server_not_finding_tx:
                self.requested_tx.pop(tx_hash)
                return
            else:
                raise
        finally:
            self._requests_answered += 1
        tx = Transaction(result)
        try:
            tx.deserialize()  # see if raises
        except Exception as e:
            # possible scenarios:
            # 1: server is sending garbage
            # 2: there is a bug in the deserialization code
            # 3: there was a segwit-like upgrade that changed the tx structure
            #    that we don't know about
            raise SynchronizerFailure(f"cannot deserialize transaction {tx_hash}") from e
        if tx_hash != tx.txid():
            raise SynchronizerFailure(f"received tx does not match expected txid ({tx_hash} != {tx.txid()})")
        tx_height = self.requested_tx.pop(tx_hash)
        self.wallet.receive_tx_callback(tx_hash, tx, tx_height)
        self.logger.info(f"received tx {tx_hash} height: {tx_height} bytes: {len(tx.raw)}")
        # callbacks
        self.wallet.network.trigger_callback('new_transaction', self.wallet, tx)

    async def main(self):
        self.wallet.set_up_to_date(False)
        # request missing txns, if any
        for addr in self.wallet.db.get_history():
            history = self.wallet.db.get_addr_history(addr)
            # Old electrum servers returned ['*'] when all history for the address
            # was pruned. This no longer happens but may remain in old wallets.
            if history == ['*']: continue
            await self._request_missing_txs(history, allow_server_not_finding_tx=True)

	# request missing txns, if tokens
        for history in self.wallet.token_history.values():
            await self.request_missing_tx_receipts(history)
            await self.request_missing_token_txs(history)

        tokens = set()
        for key in self.wallet.tokens.keys():
            token = self.wallet.tokens[key]
            tokens.add(token)
            await self.get_token_balance(token)
        await self.subscribe_tokens(tokens)

        # add addresses to bootstrap
        for addr in self.wallet.get_addresses():
            await self._add_address(addr)
        # main loop
        while True:
            await asyncio.sleep(0.1)
            await run_in_thread(self.wallet.synchronize)
            up_to_date = self.is_up_to_date()
            if (up_to_date != self.wallet.is_up_to_date()
                    or up_to_date and self._processed_some_notifications):
                self._processed_some_notifications = False
                if up_to_date:
                    self._reset_request_counters()
                self.wallet.set_up_to_date(up_to_date)
                self.wallet.network.trigger_callback('wallet_updated', self.wallet)


class Notifier(SynchronizerBase):
    """Watch addresses. Every time the status of an address changes,
    an HTTP POST is sent to the corresponding URL.
    """
    def __init__(self, network):
        SynchronizerBase.__init__(self, network)
        self.watched_addresses = defaultdict(list)  # type: Dict[str, List[str]]
        self.start_watching_queue = asyncio.Queue()

    async def main(self):
        # resend existing subscriptions if we were restarted
        for addr in self.watched_addresses:
            await self._add_address(addr)
        # main loop
        while True:
            addr, url = await self.start_watching_queue.get()
            self.watched_addresses[addr].append(url)
            await self._add_address(addr)

    async def _on_address_status(self, addr, status):
        self.logger.info(f'new status for addr {addr}')
        headers = {'content-type': 'application/json'}
        data = {'address': addr, 'status': status}
        for url in self.watched_addresses[addr]:
            try:
                async with make_aiohttp_session(proxy=self.network.proxy, headers=headers) as session:
                    async with session.post(url, json=data, headers=headers) as resp:
                        await resp.text()
            except Exception as e:
                self.logger.info(str(e))
            else:
                self.logger.info(f'Got Response for {addr}')
