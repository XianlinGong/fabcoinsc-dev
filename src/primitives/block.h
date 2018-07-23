// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FABCOIN_PRIMITIVES_BLOCK_H
#define FABCOIN_PRIMITIVES_BLOCK_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"

static const int SERIALIZE_BLOCK_LEGACY      = 0x04000000;
static const int SERIALIZE_BLOCK_NO_CONTRACT = 0x08000000;

static const int SER_WITHOUT_SIGNATURE = 1 << 3;

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    static const size_t BC_HEADER_SIZE  = 4+32+32+4+4+4;  // Bitcoin Header
    static const size_t HEADER_SIZE     = 4+32+32+4+28+4+4+32;  // Fabcoin Equihash header, add nHeight, nReserved, _nNonce, Solution  - Excluding Equihash solution
    static const size_t Q_HEADER_SIZE   = 4+32+32+4+4+4+32+32+32+4;  // Smart Contract Header , add shStateRoot, hashUTXORoot, prevoutStake, ( without  vchBlockSig ), 
    static const size_t ESC_HEADER_SIZE = 4+32+32+4+28+4+4+32+32+32+4+32;  // Fabcoin Equihash and SmartContract, Excluding Equihash solution ( without  vchBlockSig)

    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nHeight;        //Equihash 
    uint32_t nReserved[7];   //Equihash 
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint256 hashStateRoot;  // fasc
    uint256 hashUTXORoot;   // fasc
    COutPoint prevoutStake; // fasc proof-of-stake specific fields
    std::vector<unsigned char> vchBlockSig; // fasc proof-of-stake specific fields

    uint256 _nNonce;        // Equihash
    std::vector<unsigned char> nSolution;  // Equihash solution.

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        bool equihash_format = !(s.GetVersion() & SERIALIZE_BLOCK_LEGACY);
        bool has_contract = !(s.GetVersion() & SERIALIZE_BLOCK_NO_CONTRACT);

        equihash_format = false;
        has_contract = true;

        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);

        if (equihash_format) {
            READWRITE(nHeight);
            for(size_t i = 0; i < (sizeof(nReserved) / sizeof(nReserved[0])); i++) {
                READWRITE(nReserved[i]);
            }
        }
       

        READWRITE(nTime);
        READWRITE(nBits);

        if (! equihash_format) {
            READWRITE(nNonce);
        }

        if (has_contract) {
            READWRITE(hashStateRoot); // fasc
            READWRITE(hashUTXORoot); // fasc
            READWRITE(prevoutStake);
            if (!(s.GetType() & SER_WITHOUT_SIGNATURE))
               READWRITE(vchBlockSig);
        }

        if ( equihash_format ) {
            READWRITE(_nNonce);
            READWRITE(nSolution);
        } 
        /*??? else {
            uint32_t legacy_nonce = (uint32_t)nNonce.GetUint64(0);
            READWRITE(legacy_nonce);
            nNonce = ArithToUint256(arith_uint256(legacy_nonce));
        }
        */



    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nHeight = 0;
        memset(nReserved, 0, sizeof(nReserved));
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        hashStateRoot.SetNull(); // fabcoin
        hashUTXORoot.SetNull(); // fabcoin
        vchBlockSig.clear();
        prevoutStake.SetNull();
        _nNonce.SetNull();
        nSolution.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    uint256 GetHashWithoutSign() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
    
    // ppcoin: two types of block: proof-of-work or proof-of-stake
    virtual bool IsProofOfStake() const //fabcoin
    {
        return !prevoutStake.IsNull();
    }

    virtual bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }
    
    virtual uint32_t StakeTime() const
    {
        uint32_t ret = 0;
        if(IsProofOfStake())
        {
            ret = nTime;
        }
        return ret;
    }

    CBlockHeader& operator=(const CBlockHeader& other) //fabcoin
    {
        if (this != &other)
        {
            this->nVersion       = other.nVersion;
            this->hashPrevBlock  = other.hashPrevBlock;
            this->hashMerkleRoot = other.hashMerkleRoot;
            this->nHeight        = other.nHeight;
            memcpy(this->nReserved, other.nReserved, sizeof(other.nReserved));
            this->nTime          = other.nTime;
            this->nBits          = other.nBits;
            this->nNonce         = other.nNonce;
            this->hashStateRoot  = other.hashStateRoot;
            this->hashUTXORoot   = other.hashUTXORoot;
            this->vchBlockSig    = other.vchBlockSig;
            this->prevoutStake   = other.prevoutStake;
            this->_nNonce        = other._nNonce;
            this->nSolution      = other.nSolution;

        }
        return *this;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    std::pair<COutPoint, unsigned int> GetProofOfStake() const //fasc
    {
        return IsProofOfStake()? std::make_pair(prevoutStake, nTime) : std::make_pair(COutPoint(), (unsigned int)0);
    }
    
    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nHeight        = nHeight;                               //equihash
        memcpy(block.nReserved, nReserved, sizeof(block.nReserved));  //equihash
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.hashStateRoot  = hashStateRoot; // fasc
        block.hashUTXORoot   = hashUTXORoot;  // fasc
        block.vchBlockSig    = vchBlockSig;   //fasc proof-of-stake
        block.prevoutStake   = prevoutStake;  //fasc proof-of-stake
        block._nNonce        = _nNonce;       //equihash
        block.nSolution      = nSolution;     //equihash

        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // FABCOIN_PRIMITIVES_BLOCK_H
