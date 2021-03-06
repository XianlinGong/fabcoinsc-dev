#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPCs related to blockchainstate.

Test the following RPCs:
    - gettxoutsetinfo
    - getdifficulty
    - getbestblockhash
    - getblockhash
    - getblockheader
    - getchaintxstats
    - getnetworkhashps
    - verifychain

Tests correspond to code in rpc/blockchain.cpp.
"""

from decimal import Decimal
import http.client
import subprocess
import time

from test_framework.test_framework import FabcoinTestFramework
from test_framework.fabcoinconfig import INITIAL_BLOCK_REWARD, COINBASE_MATURITY

from test_framework.util import (
    assert_equal,
    assert_raises,
    assert_raises_rpc_error,
    assert_is_hex_string,
    assert_is_hash_string,
)

class BlockchainTest(FabcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-stopatheight=607']]

    def run_test(self):
        self._test_getchaintxstats()
        self._test_gettxoutsetinfo()
        self._test_getblockheader()
        self._test_getdifficulty()
        self._test_getnetworkhashps()
        self._test_stopatheight()
        assert self.nodes[0].verifychain(4, 0)

    def _test_getchaintxstats(self):
        chaintxstats = self.nodes[0].getchaintxstats(1)
        # 200 txs plus genesis tx
        assert_equal(chaintxstats['txcount'], COINBASE_MATURITY+101)
        # tx rate should be 1 per 75 second , 
        # we have to round because of binary math
        assert_equal(round(chaintxstats['txrate'] * 75, 10), Decimal(1))

    def _test_gettxoutsetinfo(self):
        node = self.nodes[0]
        res = node.gettxoutsetinfo()

        assert_equal(res['total_amount'], Decimal('12000000.00000000'))
        assert_equal(res['transactions'], COINBASE_MATURITY+100)
        assert_equal(res['height'], COINBASE_MATURITY+100)
        assert_equal(res['txouts'], COINBASE_MATURITY+100)
        assert_equal(res['bogosize'], 51000),
        assert_equal(res['bestblock'], node.getblockhash(COINBASE_MATURITY+100))
        size = res['disk_size']
        assert size > 6400
        assert size < 64000
        assert_equal(len(res['bestblock']), 64)
        assert_equal(len(res['hash_serialized_2']), 64)

        self.log.info("Test that gettxoutsetinfo() works for blockchain with just the genesis block")
        b1hash = node.getblockhash(COINBASE_MATURITY+1)
        node.invalidateblock(b1hash)

        res2 = node.gettxoutsetinfo()
        assert_equal(res2['transactions'], COINBASE_MATURITY)
        assert_equal(res2['total_amount'], Decimal('10000000'))
        assert_equal(res2['height'], COINBASE_MATURITY)
        assert_equal(res2['txouts'], COINBASE_MATURITY)
        assert_equal(res2['bogosize'], 42500),
        assert_equal(res2['bestblock'], node.getblockhash(COINBASE_MATURITY))
        assert_equal(len(res2['hash_serialized_2']), 64)

        self.log.info("Test that gettxoutsetinfo() returns the same result after invalidate/reconsider block")
        node.reconsiderblock(b1hash)

        res3 = node.gettxoutsetinfo()
        assert_equal(res['height'], res3['height'])
        assert_equal(res['total_amount'], res3['total_amount'])
        assert_equal(res['transactions'], res3['transactions'])
        assert_equal(res['txouts'], res3['txouts'])
        assert_equal(res['bogosize'], res3['bogosize'])
        assert_equal(res['bestblock'], res3['bestblock'])
        assert_equal(res['hash_serialized_2'], res3['hash_serialized_2'])

    def _test_getblockheader(self):
        node = self.nodes[0]

        assert_raises_rpc_error(-5, "Block not found",
                              node.getblockheader, "nonsense")

        besthash = node.getbestblockhash()
        secondbesthash = node.getblockhash(COINBASE_MATURITY+99)
        header = node.getblockheader(besthash)

        assert_equal(header['hash'], besthash)
        assert_equal(header['height'], COINBASE_MATURITY+100)
        assert_equal(header['confirmations'], 1)
        assert_equal(header['previousblockhash'], secondbesthash)
        assert_is_hex_string(header['chainwork'])
        assert_is_hash_string(header['hash'])
        assert_is_hash_string(header['previousblockhash'])
        assert_is_hash_string(header['merkleroot'])
        assert_is_hash_string(header['bits'], length=None)
        assert isinstance(header['time'], int)
        assert isinstance(header['mediantime'], int)
        assert isinstance(header['nonce'], int)
        assert isinstance(header['version'], int)
        assert isinstance(int(header['versionHex'], 16), int)
        assert isinstance(header['difficulty'], Decimal)

    def _test_getdifficulty(self):
        difficulty = self.nodes[0].getdifficulty()
        # 1 hash in 2 should be valid, so difficulty should be 1/2**31
        # binary => decimal => binary math is why we do this check
        assert abs(difficulty['proof-of-work'] * 2**31 - 1) < 0.0001

    def _test_getnetworkhashps(self):
        hashes_per_second = self.nodes[0].getnetworkhashps()
        # This should be 2 hashes every 10 minutes or 1/300
        assert abs(hashes_per_second * 300 - 1) < 10

    def _test_stopatheight(self):
        assert_equal(self.nodes[0].getblockcount(), COINBASE_MATURITY+100)
        self.nodes[0].generate(6)
        assert_equal(self.nodes[0].getblockcount(), COINBASE_MATURITY+106)
        self.log.debug('Node should not stop at this height')
        assert_raises(subprocess.TimeoutExpired, lambda: self.nodes[0].process.wait(timeout=3))
        try:
            self.nodes[0].generate(1)
        except (ConnectionError, http.client.BadStatusLine):
            pass  # The node already shut down before response
        self.log.debug('Node should stop at this height...')
        self.nodes[0].wait_until_stopped()
        self.start_node(0)
        assert_equal(self.nodes[0].getblockcount(), COINBASE_MATURITY+107)


if __name__ == '__main__':
    BlockchainTest().main()
