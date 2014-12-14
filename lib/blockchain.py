#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import threading, time, Queue, os, sys, shutil, traceback, json, auxpow
import zlib
from util import user_dir, appdata_dir, print_error, cdiv
from bitcoin import *

from transaction import BCDataStream

try:
    from ltc_scrypt import getPoWHash as PoWHash
except ImportError:
    print_msg("Warning: ltc_scrypt not available, using fallback")
    from scrypt import scrypt_1024_1_1_80 as PoWHash

import pprint
pp = pprint.PrettyPrinter(indent=4)

#max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
max_target = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

# https://github.com/dogecoin/dogecoin/blob/65228644e10328172e9fa3ebe64251983e1153b3/src/core.h#L39
auxpow_start = 371337
# https://github.com/dogecoin/dogecoin/blob/master/src/main.cpp#L1253
digishield_start = 145000

class Blockchain(threading.Thread):

    def __init__(self, config, network):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.network = network
        self.lock = threading.Lock()
        self.local_height = 0
        self.running = False
        self.headers_url = 'https://electrum-doge.com/dogecoin/blockchain_headers'
        self.set_local_height()
        self.queue = Queue.Queue()


    def height(self):
        return self.local_height


    def stop(self):
        with self.lock: self.running = False


    def is_running(self):
        with self.lock: return self.running


    def run(self):
        self.init_headers_file()
        self.set_local_height()
        print_error( "blocks:", self.local_height )

        with self.lock:
            self.running = True

        while self.is_running():

            try:
                result = self.queue.get()
            except Queue.Empty:
                continue

            if not result: continue

            i, header = result
            if not header: continue

            height = header.get('block_height')

            if height <= self.local_height:
                continue

            if height > self.local_height + 50:
                if not self.get_and_verify_chunks(i, header, height):
                    continue

            if height > self.local_height:
                # get missing parts from interface (until it connects to my chain)
                chain = self.get_chain( i, header )

                # skip that server if the result is not consistent
                if not chain:
                    print_error('e')
                    continue

                # verify the chain
                if self.verify_chain( chain ):
                    print_error("height:", height, i.server)
                    for header in chain:
                        self.save_header(header)
                else:
                    print_error("error", i.server)
                    # todo: dismiss that server
                    continue


            self.network.new_blockchain_height(height, i)



    def verify_chain(self, chain):

        first_header = chain[0]
        prev_header = self.read_header(first_header.get('block_height') - 1)

        for header in chain:

            height = header.get('block_height')

            prev_hash = self.hash_header(prev_header)
            bits, target = self.get_target(height, chain)
            _hash = self.hash_header(header)
            pow_hash = self.pow_hash_header(header)

            try:
                # todo: dogecoin auxpow block version
                if height >= auxpow_start and header['version'] == 6422786:
                    assert auxpow.verify(_hash, auxpow.get_our_chain_id(), header['auxpow'])
                    pow_hash = self.pow_hash_header(header['auxpow']['parent_block'])
                assert prev_hash == header.get('prev_block_hash')
                assert bits == header.get('bits')
                assert int('0x'+pow_hash,16) < target
            except Exception:
                print traceback.format_exc()
                print 'error validating chain at height ', height
                print 'block ', height, '(',_hash,') failed validation'
                pprint.pprint(header)
                print hex(bits), '==', hex(header.get('bits'))
                print int('0x'+pow_hash,16), '<', target
                return False

            prev_header = header

        return True



    def verify_chunk(self, index, hexdata):
        print 'verify chunk'
        hex_to_int = lambda s: int('0x' + s[::-1].encode('hex'), 16)

        data = hexdata.decode('hex')
        disk_data = ''
        height = index * 2016
        num = hex_to_int(data[0:4])
        data = data[4:]

        auxpowdata = data[num*88:]
        auxpowbaseoffset = 0

        if index == 0:
            previous_hash = ("0"*64)
        else:
            prev_header = self.read_header(index*2016-1)
            if prev_header is None: raise
            previous_hash = self.hash_header(prev_header)

        bits, target = self.get_target(height)

        chain = []
        for i in range(num):
            height = index * 2016 + i

            raw_header = data[i*88:(i+1)*88]
            disk_data += raw_header[0:80] # strip auxpow data

            header = self.header_from_string(raw_header)
            _hash = self.pow_hash_header(header)
            _prev_hash = self.hash_header(header)
            header['block_height'] = height

            if (i == 0):
               auxpowbaseoffset = header['auxpow_offset']

            start = header['auxpow_offset'] - auxpowbaseoffset
            end = start + header['auxpow_length']

            if (end > start):
                header['auxpow'] = self.auxpow_from_string(auxpowdata[start:end].decode('hex'))
                #print header['auxpow']

            chain.append(header)

            # dogecoin retargets: every 240 blocks (until digishield)
            if (height % 240 == 0):
                #print height , '%', 144 , '=', height % 144
                bits, target = self.get_target(height, chain)

            # after digishield, retarget at every block
            if (height > digishield_start):
                bits, target = self.get_target(height, chain)


            if height >= auxpow_start and header['version'] == 6422786: #TODO getAuxPowVersion()
                #todo: check that auxpow.get_chain_id(header) == auxpow.get_our_chain_id?
                #print header['auxpow']
                try:
                    assert auxpow.verify(_prev_hash, auxpow.get_our_chain_id(), header['auxpow'])
                except Exception as e:
                    print traceback.format_exc()
                    print 'block ', height, '(',_hash,') failed validation'
                    print 'auxpow failed verification'
                    pp.pprint(header['auxpow'])
                    raise e
                #pp.pprint(parent_header)
                _hash = self.pow_hash_header(header['auxpow']['parent_block'])
                #print _hash
                # todo: verify auxpow data
                #_hash = '' # auxpow.getHash()

            try:
                assert previous_hash == header.get('prev_block_hash')
                assert bits == header.get('bits')
                assert int('0x'+_hash,16) < target
            except Exception as e:
                print 'block ', height, ' failed validation'
                print previous_hash, '==', header.get('prev_block_hash')
                print hex(bits), '==', hex(header.get('bits'))
                print int('0x'+_hash,16), '<', target
                raise e

            if height % 240 == 0:
                print 'block ', height, ' validated'

            previous_header = header
            previous_hash = _prev_hash

        self.save_chunk(index, disk_data)
        print_error("validated chunk %d"%height)

    #def parent_block_to_header(self, parent_block):
        #h = {}
        #h['version'] = parent_block['version']
        #h['prev_block_hash'] = parent_block['previousblockhash']
        #h['merkle_root'] = parent_block['merkleroot']
        #h['timestamp'] = parent_block['time']
        #h['bits'] = int(parent_block['bits'], 16) #not sure
        #h['nonce'] = parent_block['nonce']
        #return h

    def header_to_string(self, res):
        s = int_to_hex(res.get('version'),4) \
            + rev_hex(res.get('prev_block_hash')) \
            + rev_hex(res.get('merkle_root')) \
            + int_to_hex(int(res.get('timestamp')),4) \
            + int_to_hex(int(res.get('bits')),4) \
            + int_to_hex(int(res.get('nonce')),4)
        return s

    def auxpow_from_string(self, s):
        res = {}
        res['coinbasetx'], s = tx_from_string(s)
        res['coinbaseMerkleBranch'], res['coinbaseIndex'], s = merkle_branch_from_string(s)
        res['chainMerkleBranch'], res['chainIndex'], s = merkle_branch_from_string(s)
        res['parent_block'] = header_from_string(s)
        return res


    def header_from_string(self, s):
        # hmmm why specify 0x at beginning if 16 is already specified??
        hex_to_int = lambda s: int('0x' + s[::-1].encode('hex'), 16)
        h = {}
        h['version'] = hex_to_int(s[0:4])
        h['prev_block_hash'] = hash_encode(s[4:36])
        h['merkle_root'] = hash_encode(s[36:68])
        h['timestamp'] = hex_to_int(s[68:72])
        h['bits'] = hex_to_int(s[72:76])
        h['nonce'] = hex_to_int(s[76:80])
        if (len(s) > 80):
            h['auxpow_offset'] = hex_to_int(s[80:84])
            h['auxpow_length'] = hex_to_int(s[84:88])
        return h

    def pow_hash_header(self, header):
        return rev_hex(PoWHash(self.header_to_string(header).decode('hex')).encode('hex'))

    def hash_header(self, header):
        return rev_hex(Hash(self.header_to_string(header).decode('hex')).encode('hex'))

    def path(self):
        return os.path.join( self.config.path, 'blockchain_headers')

    # the file hosted on the server has extra data to index auxpow data
    # we need to remove that data to have 80 byte block headers instead of 88
    def remove_auxpow_indexes(self, filename):
        size = os.path.getsize(filename)
        f = open(self.path(), 'wb+')
        fa = open(filename, 'rb')

        i = 0
        j = 0
        while (i < size):
            fa.seek(i)
            f.seek(j)
            chunk = fa.read(80)
            f.write(chunk)
            j += 80
            i += 88

        f.close()
        fa.close()
        os.remove(filename)

    def init_headers_file(self):
        filename = self.path()
        if os.path.exists(filename):
            return

        try:
            import urllib, socket
            socket.setdefaulttimeout(30)
            print_error('downloading ', self.headers_url )
            urllib.urlretrieve(self.headers_url, filename + '_auxpow')
            self.remove_auxpow_indexes(filename + '_auxpow')
            print_error("done.")
        except Exception:
            print_error( 'download failed. creating file', filename + '_auxpow' )
            open(filename,'wb+').close()

    def save_chunk(self, index, chunk):
        filename = self.path()
        f = open(filename,'rb+')
        f.seek(index*2016*80)
        h = f.write(chunk)
        f.close()
        self.set_local_height()

    def truncate_headers(self, height):
        filename = self.path()
        f = open(filename,'rb+')
        f.truncate(height*80)
        f.close()
        self.set_local_height()

    def erase_chunk(self, index):
        filename = self.path()
        f = open(filename,'rb+')
        f.truncate(index*2016*80)
        f.close()
        self.set_local_height()

    def save_header(self, header):
        data = self.header_to_string(header).decode('hex')
        assert len(data) == 80
        height = header.get('block_height')
        filename = self.path()
        f = open(filename,'rb+')
        f.seek(height*80)
        h = f.write(data)
        f.close()
        self.set_local_height()


    def set_local_height(self):
        name = self.path()
        if os.path.exists(name):
            h = os.path.getsize(name)/80 - 1
            if self.local_height != h:
                self.local_height = h


    def read_header(self, block_height):
        name = self.path()
        if os.path.exists(name):
            f = open(name,'rb')
            f.seek(block_height*80)
            h = f.read(80)
            f.close()
            if len(h) == 80:
                h = self.header_from_string(h)
                return h

    def get_target(self, height, chain=None):
        if chain is None:
            chain = []  # Do not use mutables as default values!

        if height < 240: return 0x1e0ffff0, 0x00000FFFF0000000000000000000000000000000000000000000000000000000

        nTargetTimespan = 4*60*60 #dogecoin: every 4 hours
        nTargetTimespanNEW = 60 #dogecoin: every 1 minute

        nTargetSpacing = 60 #dogecoin: 1 minute
        nInterval = nTargetTimespan / nTargetSpacing #240

        retargetTimespan = nTargetTimespan
        retargetInterval = nInterval

        if height > digishield_start:
            retargetInterval =  nTargetTimespanNEW / nTargetSpacing #1
            retargetTimespan = nTargetTimespanNEW

        blockstogoback = retargetInterval - 1
        if (height != retargetInterval):
            blockstogoback = retargetInterval

        latest_retarget_height = (height / retargetInterval) * retargetInterval
        #print 'latest_retarget_height', latest_retarget_height
        last_height = latest_retarget_height - 1
        first_height = last_height - blockstogoback

        #print 'first height', first_height
        #print 'last height', last_height

        first = self.read_header(first_height)
        last = self.read_header(last_height)

        #print 'first'
        #print first
        #print 'last'
        #print last

        if first is None:
            for h in chain:
                if h.get('block_height') == first_height:
                    first = h

        if last is None:
            for h in chain:
                if h.get('block_height') == last_height:
                    last = h

        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nModulatedTimespan = nActualTimespan

        if height <= 5000:
            nModulatedTimespan = max(nModulatedTimespan, cdiv(nTargetTimespan, 16))
            nModulatedTimespan = min(nModulatedTimespan, nTargetTimespan*4)
        elif height <= 10000:
            nModulatedTimespan = max(nModulatedTimespan, cdiv(nTargetTimespan, 8))
            nModulatedTimespan = min(nModulatedTimespan, nTargetTimespan*4)
        elif height <= digishield_start:
            nModulatedTimespan = max(nModulatedTimespan, cdiv(nTargetTimespan, 4))
            nModulatedTimespan = min(nModulatedTimespan, nTargetTimespan*4)
        # digishield
        # https://github.com/dogecoin/dogecoin/blob/master/src/main.cpp#L1354
        else:
            nModulatedTimespan = retargetTimespan + cdiv(nModulatedTimespan - retargetTimespan, 8)
            nModulatedTimespan = max(nModulatedTimespan, retargetTimespan - cdiv(retargetTimespan, 4))
            nModulatedTimespan = min(nModulatedTimespan, retargetTimespan + cdiv(retargetTimespan, 2))

        bits = last.get('bits')

        #print 'before', hex(bits)
        #print 'nActualTimespan', nActualTimespan
        #print 'nTargetTimespan', nTargetTimespan
        #print 'retargetTimespan', retargetTimespan
        #print 'nModulatedTimespan', nModulatedTimespan

        return self.get_target_from_timespans(bits, nModulatedTimespan, retargetTimespan)

    def get_target_from_timespans(self, bits, nActualTimespan, nTargetTimespan):

        # convert to bignum
        MM = 256*256*256
        a = bits%MM
        if a < 0x8000:
            a *= 256
        target = (a) * pow(2, 8 * (bits/MM - 3))

        # new target
        new_target = min( max_target, cdiv(target * nActualTimespan, nTargetTimespan) )

        # convert it to bits
        c = ("%064X"%new_target)[2:]
        i = 31
        while c[0:2]=="00":
            c = c[2:]
            i -= 1

        c = int('0x'+c[0:6],16)
        if c >= 0x800000:
            c /= 256
            i += 1

        new_bits = c + MM * i

        #print 'new target: ', hex(new_target)
        return new_bits, new_target

    def request_header(self, i, h, queue):
        print_error("requesting header %d from %s"%(h, i.server))
        i.send_request({'method':'blockchain.block.get_header', 'params':[h]}, queue)

    def retrieve_request(self, queue):
        while True:
            try:
                ir = queue.get(timeout=1)
            except Queue.Empty:
                print_error('blockchain: request timeout')
                continue
            i, r = ir
            result = r['result']
            return result

    def get_chain(self, interface, final_header):

        header = final_header
        chain = [ final_header ]
        requested_header = False
        queue = Queue.Queue()

        while self.is_running():

            if requested_header:
                header = self.retrieve_request(queue)
                if not header: return
                chain = [ header ] + chain
                requested_header = False

            height = header.get('block_height')
            previous_header = self.read_header(height -1)
            if not previous_header:
                self.request_header(interface, height - 1, queue)
                requested_header = True
                continue

            # verify that it connects to my chain
            prev_hash = self.hash_header(previous_header)
            if prev_hash != header.get('prev_block_hash'):
                print_error("reorg")
                # truncate headers file
                self.truncate_headers(height - 2)
                self.request_header(interface, height - 1, queue)
                requested_header = True
                continue

            else:
                # the chain is complete
                return chain


    def get_and_verify_chunks(self, i, header, height):

        queue = Queue.Queue()
        min_index = (self.local_height + 1)/2016
        max_index = (height + 1)/2016
        n = min_index
        while n < max_index + 1:
            print_error( "Requesting chunk:", n )
            # todo: dogecoin get_auxblock_chunk after block 45000...?
            # todo: call blockchain.block.get_auxblock from verify_chunk instead?
            i.send_request({'method':'blockchain.block.get_chunk', 'params':[n]}, queue)
            r = self.retrieve_request(queue)

            #print 'chunk compressed length : ', len(r)
            r = zlib.decompress(r.decode('hex'))
            #print 'chunk uncompressed length : ', len(r)

            try:
                self.verify_chunk(n, r)
                n = n + 1
            except Exception:
                print traceback.format_exc()
                print_error('Verify chunk failed!')
                self.erase_chunk(n)
                n = n - 1
                if n < 0:
                    return False

        return True

# START electrum-doge-server
# the following code was copied from the server's utils.py file
def tx_from_string(s):
    vds = BCDataStream()
    vds.write(s)
    #vds.write(raw.decode('hex'))
    d = {}
    d['version'] = vds.read_int32()
    n_vin = vds.read_compact_size()
    d['vin'] = []
    for i in xrange(n_vin):
        txin = {}
        # dirty hack: add outpoint structure to get correct txid later
        outpoint_pos = vds.read_cursor
        txin['coinbase'] = vds.read_bytes(vds.read_compact_size()).encode('hex')
        txin['sequence'] = vds.read_uint32()
        d['vin'].append(txin)
    n_vout = vds.read_compact_size()
    d['vout'] = []
    for i in xrange(n_vout):
        txout = {}
        txout['value'] = vds.read_int64()
        txout['scriptPubKey'] = vds.read_bytes(vds.read_compact_size()).encode('hex')
        d['vout'].append(txout)
    d['lockTime'] = vds.read_uint32()

    # compute txid
    # dirty hack to insert coinbase outpoint structure before hashing
    raw = s[0:outpoint_pos]
    COINBASE_OP = '0' * 64 + 'F' * 8
    raw += (COINBASE_OP).decode('hex')
    raw += s[outpoint_pos:vds.read_cursor]

    d['txid'] = Hash(raw)[::-1].encode('hex')

    return d, s[vds.read_cursor:] # +1?

def merkle_branch_from_string(s):
    vds = BCDataStream()
    vds.write(s)
    #vds.write(raw.decode('hex'))
    hashes = []
    n_hashes = vds.read_compact_size()
    for i in xrange(n_hashes):
        _hash = vds.read_bytes(32)
        hashes.append(hash_encode(_hash))
    index = vds.read_int32()
    return hashes, index, s[vds.read_cursor:]

def hex_to_int(s):
    return int('0x' + s[::-1].encode('hex'), 16)


def header_from_string(s):
    #OK dogecoin todo: include auxpow position in auxpow file (offset(s))
    res = {
        'version': hex_to_int(s[0:4]),
        'prev_block_hash': hash_encode(s[4:36]),
        'merkle_root': hash_encode(s[36:68]),
        'timestamp': hex_to_int(s[68:72]),
        'bits': hex_to_int(s[72:76]),
        'nonce': hex_to_int(s[76:80]),
    }

    if (len(s) > 80):
        res['auxpow_offset'] = hex_to_int(s[80:84])
        res['auxpow_length'] = hex_to_int(s[84:88])

    return res
# END electrum-doge-server


