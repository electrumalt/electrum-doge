# https://github.com/kR105/i0coin/compare/bitcoin:master...master#diff-d3b948fe89a5d012a7eaeea8f25d7c42R1
import string
import btcutils

BLOCK_VERSION_CHAIN_START = (1 << 16)

def get_our_chain_id():
    #https://github.com/dogecoin/dogecoin/blob/65228644e10328172e9fa3ebe64251983e1153b3/src/core.h#L38
    return 0x0062 #dogecoin

def get_chain_id(header):
    return header['version'] / BLOCK_VERSION_CHAIN_START

def check_merkle_branch(hash, merkle_branch, index):
    return btcutils.check_merkle_branch(hash, merkle_branch, index)

# https://github.com/kR105/i0coin/compare/bitcoin:master...master#diff-610df86e65fce009eb271c2a4f7394ccR262
def calc_merkle_index(chain_id, nonce, merkle_size):
    rand = nonce
    rand = (rand * 1103515245 + 12345) & 0xffffffff
    rand += chain_id
    rand = (rand * 1103515245 + 12345) & 0xffffffff
    return rand % merkle_size

def verify(auxhash, chain_id, auxpow):
    parent_block = auxpow['parent_block']
    coinbase = auxpow['coinbasetx']
    coinbase_hash = coinbase['txid']

    chain_merkle_branch = auxpow['chainMerkleBranch']
    chain_index = auxpow['chainIndex']

    coinbase_merkle_branch = auxpow['coinbaseMerkleBranch']
    coinbase_index = auxpow['coinbaseIndex']

    #if (get_chain_id(parent_block) == chain_id)
    #  return error("Aux POW parent has our chain ID");

    if (get_chain_id(parent_block) == chain_id):
        print 'Aux POW parent has our chain ID'
        return False

    #// Check that the chain merkle root is in the coinbase
    #uint256 nRootHash = CBlock::CheckMerkleBranch(hashAuxBlock, vChainMerkleBranch, nChainIndex);
    #vector<unsigned char> vchRootHash(nRootHash.begin(), nRootHash.end());
    #std::reverse(vchRootHash.begin(), vchRootHash.end()); // correct endian

    # Check that the chain merkle root is in the coinbase
    root_hash = check_merkle_branch(auxhash, chain_merkle_branch, chain_index)

    # Check that we are in the parent block merkle tree
    # if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != parentBlock.hashMerkleRoot)
    #    return error("Aux POW merkle root incorrect");
    if (check_merkle_branch(coinbase_hash, coinbase_merkle_branch, coinbase_index) != parent_block['merkle_root']):
        print 'Aux POW merkle root incorrect'
        return False

    #// Check that the same work is not submitted twice to our chain.
    #//

    #CScript::const_iterator pcHead =
        #std::search(script.begin(), script.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader));

    #CScript::const_iterator pc =
        #std::search(script.begin(), script.end(), vchRootHash.begin(), vchRootHash.end());

    #if (pc == script.end())
        #return error("Aux POW missing chain merkle root in parent coinbase");

    script = coinbase['vin'][0]['coinbase']
    pos = string.find(script, root_hash)

    # todo: if pos == -1 ??
    if pos == -1:
        print 'Aux POW missing chain merkle root in parent coinbase'
        return False

    #todo: make sure only submitted once
    #if (pcHead != script.end())
    #{
        #// Enforce only one chain merkle root by checking that a single instance of the merged
        #// mining header exists just before.
        #if (script.end() != std::search(pcHead + 1, script.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader)))
            #return error("Multiple merged mining headers in coinbase");
        #if (pcHead + sizeof(pchMergedMiningHeader) != pc)
            #return error("Merged mining header is not just before chain merkle root");
    #}
    #else
    #{
        #// For backward compatibility.
        #// Enforce only one chain merkle root by checking that it starts early in the coinbase.
        #// 8-12 bytes are enough to encode extraNonce and nBits.
        #if (pc - script.begin() > 20)
            #return error("Aux POW chain merkle root must start in the first 20 bytes of the parent coinbase");
    #}


    #// Ensure we are at a deterministic point in the merkle leaves by hashing
    #// a nonce and our chain ID and comparing to the index.
    #pc += vchRootHash.size();
    #if (script.end() - pc < 8)
        #return error("Aux POW missing chain merkle tree size and nonce in parent coinbase");

    pos = pos + len(root_hash)
    if (len(script) - pos < 8):
        print 'Aux POW missing chain merkle tree size and nonce in parent coinbase'
        return false

     #int nSize;
    #memcpy(&nSize, &pc[0], 4);
    #if (nSize != (1 << vChainMerkleBranch.size()))
        #return error("Aux POW merkle branch size does not match parent coinbase");

    def hex_to_int(s):
        s = s.decode('hex')[::-1].encode('hex')
        return int(s, 16)

    size = hex_to_int(script[pos:pos+8])
    nonce = hex_to_int(script[pos+8:pos+16])

    #print 'size',size
    #print 'nonce',nonce
    #print '(1 << len(chain_merkle_branch)))', (1 << len(chain_merkle_branch))
    #size = hex_to_int(script[pos:pos+4])
    #nonce = hex_to_int(script[pos+4:pos+8])

    if (size != (1 << len(chain_merkle_branch))):
        print 'Aux POW merkle branch size does not match parent coinbase'
        return False

    #int nNonce;
    #memcpy(&nNonce, &pc[4], 4);
    #// Choose a pseudo-random slot in the chain merkle tree
    #// but have it be fixed for a size/nonce/chain combination.
    #//
    #// This prevents the same work from being used twice for the
    #// same chain while reducing the chance that two chains clash
    #// for the same slot.
    #unsigned int rand = nNonce;
    #rand = rand * 1103515245 + 12345;
    #rand += nChainID;
    #rand = rand * 1103515245 + 12345;

    #if (nChainIndex != (rand % nSize))
        #return error("Aux POW wrong index");

    index = calc_merkle_index(chain_id, nonce, size)
    #print 'index', index

    if (chain_index != index):
        print 'Aux POW wrong index'
        return False

    return True


if __name__ == "__main__":
    #testing
    #auxpow= {  
       #'parent_block':{  
          #'merkle_root':'11feeb10dd38c4c7f5069113fdc9d98509e431abbd4b4746951c7b5ca8872d86',
          #'nonce':220414812,
          #'previousblockhash':'0000000000000191065f88ab70f4103ff11f060ba916f1e0c0354451e4709824',
          #'hash':'00000000002a20a2839a0802830a7fe3e2def157f5df7edfa8771cf5e8c0a9cc',
          #'version':1,
          #'time':1325305711,
          #'bits':'1a0e76ba'
       #},
       #'chainMerkleBranch':[  
          #'1d18e96bcbb4632d89c85145b1f65c4da5c099215edaeb882773a28ea2efdca4',
          #'66000ba5cecf913ef18854823312921ad97869dd37de07a36d563cbe97a9d879'
       #],
       #'coinbaseMerkleBranch':[  
          #'37758df045b2fc1548c052153adbe67768cef6a733d0b6d2063cc1e3ff21b5c3',
          #'3d65957eaa177b49ba38de1e48fa1a972d189fc2d0d86781d052ece71b2943cd',
          #'090e0e458d262d4fa5a56ddd44677aef742d58d26fa431475ae3b87732dcee6a',
          #'74aecba6f266ab3fddd6846745802d12d85534fb7b06d5fa0bc927e9ce5267b0',
          #'eda7e0398b46616358bb15b892f35007e7329b7e5752c252f49c43928883ee34',
          #'0a4c49d9319698e89638b69d68b514ef70314d26cb4fdda6fe951b429be100b3'
       #],
       #'coinbaseIndex':0,
       #'chainIndex':1,
       #'coinbasetx':{  
          #'locktime':0,
          #'version':1,
          #'vin':[  
             #{  
                #'coinbase':'04ba760e1a0155522cfabe6d6dc52d147bbf91815a4b534506729896920e6f39980d8e8d4ef78fa4429b1516c80400000000000000',
                #'sequence':4294967295
             #}
          #],
          #'vout':[  
             #{  
                #'n':0,
                #'value':50.02165,
                #'scriptPubKey':{  
                   #'reqSigs':1,
                   #'hex':'4104bb8a2a4d2351687274e3daed6b3f7303c7115e593bce6b908a096f0ac071067fb820b0a7b12f0cdeac9bcf1ad1f19b4ecce90cf6a953d05dabed19b42557cadfac',
                   #'addresses':[  
                      #'xd3k7hgQHHD6rdeGToCm2G8Z26LK1LjK9S'
                   #],
                   #'asm':'04bb8a2a4d2351687274e3daed6b3f7303c7115e593bce6b908a096f0ac071067fb820b0a7b12f0cdeac9bcf1ad1f19b4ecce90cf6a953d05dabed19b42557cadf OP_CHECKSIG',
                   #'type':'pubkey'
                #}
             #}
          #],
          #'txid':'87c04be9d0522cc17fbb35828f4eb583328cf0e5b4616f2415fc018e6ef94196'
       #},
       #'size':558
    #}
    auxpow = {'parent_block': {'nonce': 220414812, 'prev_block_hash': '0000000000000191065f88ab70f4103ff11f060ba916f1e0c0354451e4709824', 'timestamp': 1325305711, 'merkle_root': '11feeb10dd38c4c7f5069113fdc9d98509e431abbd4b4746951c7b5ca8872d86', 'version': 1, 'bits': 437155514}, 'chainMerkleBranch': ['1d18e96bcbb4632d89c85145b1f65c4da5c099215edaeb882773a28ea2efdca4', '66000ba5cecf913ef18854823312921ad97869dd37de07a36d563cbe97a9d879'], 'coinbaseMerkleBranch': ['37758df045b2fc1548c052153adbe67768cef6a733d0b6d2063cc1e3ff21b5c3', '3d65957eaa177b49ba38de1e48fa1a972d189fc2d0d86781d052ece71b2943cd', '090e0e458d262d4fa5a56ddd44677aef742d58d26fa431475ae3b87732dcee6a', '74aecba6f266ab3fddd6846745802d12d85534fb7b06d5fa0bc927e9ce5267b0', 'eda7e0398b46616358bb15b892f35007e7329b7e5752c252f49c43928883ee34', '0a4c49d9319698e89638b69d68b514ef70314d26cb4fdda6fe951b429be100b3'], 'coinbaseIndex': 0, 'coinbasetx': {'lockTime': 0, 'version': 1, 'vin': [{'coinbase': '04ba760e1a0155522cfabe6d6dc52d147bbf91815a4b534506729896920e6f39980d8e8d4ef78fa4429b1516c80400000000000000', 'sequence': 4294967295}], 'vout': [{'value': 5002165000, 'scriptPubKey': '4104bb8a2a4d2351687274e3daed6b3f7303c7115e593bce6b908a096f0ac071067fb820b0a7b12f0cdeac9bcf1ad1f19b4ecce90cf6a953d05dabed19b42557cadfac'}]}, 'chainIndex': 1}

    header = {'auxpow_length': 1700,
        'auxpow_offset': 0,
        'bits': 461017156,
        'merkle_root': '6ea3984bd09238c0a3b05282d7971c4f1ccc1df9361ba7e61be43d4228771715',
        'nonce': 0,
        'prev_block_hash': '00000000006bc8bf1468fbb495bad554d8d16740f8b88e67003f0052c90a6aa7',
        'timestamp': 1325305695,
        'version': 196865}

    #print get_chain_id(header)
    #print get_chain_id(auxpow['parent_block'])

    print verify('6aa64d34307e3a3c062be612af6ce8a262b05c0f4aa9b41f23db9c0bd3c935f1', 3, auxpow)
