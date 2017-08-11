// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2014-2017 The MonetaryUnit Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

#include "stdio.h"
#include "pow.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

    return genesis;
}


static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Stasis Genesis Block";
    const CScript genesisOutputScript = CScript() << ParseHex("0446a60b89dcabfce423350a32b177199622991a5e19adaec943c835e8d83cc07c346d5e62cb3bf3b518e25fe2d051fd794956e0686b357a32bbdb542e84b1b6c7") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */


class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
              consensus.nSubsidyHalvingInterval = -1;
              consensus.nMasternodePaymentsStartBlock = 10000;
              consensus.nMasternodePaymentsIncreaseBlock = -1;
              consensus.nMasternodePaymentsIncreasePeriod = -1;
              consensus.nInstantSendKeepLock = 94;
              consensus.nBudgetPaymentsStartBlock = 100000;
              consensus.nBudgetPaymentsCycleBlocks = 100;
              consensus.nBudgetPaymentsWindowBlocks = 150;
              consensus.nBudgetProposalEstablishingTime = 86400;
              consensus.nSuperblockStartBlock = 10000;
              consensus.nSuperblockCycle = 64800;
              consensus.nGovernanceMinQuorum = 10;
              consensus.nGovernanceFilterElements = 20000;
              consensus.nMasternodeMinimumConfirmations = 20;

              consensus.nMajorityEnforceBlockUpgrade = 750;
              consensus.nMajorityRejectBlockOutdated = 950;

              consensus.nMajorityWindow = 3900;
              consensus.BIP34Height = -1;
              consensus.BIP34Hash = uint256S("0x0");
              consensus.powLimit = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
              consensus.nPowTargetTimespan = 120;
              consensus.nPowTargetSpacing = 60;
              consensus.fPowAllowMinDifficultyBlocks = false;
              consensus.fPowNoRetargeting = false;
              consensus.nRuleChangeActivationThreshold = 2;
              consensus.nMinerConfirmationWindow = 3;

              consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
              consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
              consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008
              // Deployment of BIP68, BIP112, and BIP113.
              consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
              consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1486252800; // Feb 5th, 2017
              consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517788800; // Feb 5th, 2018

              /**
               * The message start string is designed to be unlikely to occur in normal data.
               * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
               * a large 32-bit integer with any alignment.
               */

              pchMessageStart[0] = 0xff;
              pchMessageStart[1] = 0xfe;
              pchMessageStart[2] = 0xff;
              pchMessageStart[3] = 0xc3;

              vAlertPubKey = ParseHex("0446a60b89dcabfce423350a32b177199622991a5e19adaec943c835e8d83cc07c346d5e62cb3bf3b518e25fe2d051fd794956e0686b357a32bbdb542e84b1b6c7");
              nDefaultPort = 19683;
              nMaxTipAge = 28800;
              nPruneAfterHeight = 100000;


              genesis = CreateGenesisBlock(1500503122, 368296, 0x1e0ffff0, 1, 50 * COIN);
              consensus.hashGenesisBlock = genesis.GetHash();
              assert(consensus.hashGenesisBlock == uint256S("0x00000d0ce995bc9f530ed3a9a87721d76222078778f1206edfa3f0527541e342"));
              assert(genesis.hashMerkleRoot == uint256S("0xaa920cef2c0994e0480c2525054d150477eb779e5e774ae88961a80999378a08"));

              vSeeds.push_back(CDNSSeedData("159.203.109.115","159.203.109.115"));

        // MonetaryUnit addresses start with '7'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        // MonetaryUnit script addresses start with 'X'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        // MonetaryUnit private keys start with 's' or 't'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);

        // MonetaryUnit BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // MonetaryUnit BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        // MonetaryUnit BIP44 coin type is '5' <== Should be migrated to 31 SLIP-44 MonetaryUnit
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x05).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 950;
        strSporkPubKey = "04251df9125d968a5efeac89f08be613621ae19d3d9ca4818485d2405a994b6164d9f26c5ad3e7a19a99dc36fa7dd03f05e968b4bdd1dc39e5b25c0dc60a441506";
        strMasternodePaymentsPubKey = "0483bbc11d4c6a0cb4361da2a234912a7e174e2b9ecfb7685920c24a58fa32205d73f272540032ec7f4dd9d7d865bf171268dcacaa1184675cb2ed2361eb93218f";

        checkpointData = (CCheckpointData) {
                boost::assign::map_list_of
                (0, uint256S("0x00000cc017736326ba8a4bedc19ebe0df04ad75f4e1f5660f2b717b9f0cdb714"))
                (0, uint256S("0x00000cc017736326ba8a4bedc19ebe0df04ad75f4e1f5660f2b717b9f0cdb714")),
                1498541029,
                       197,   //   (the tx=... number in the SetBestChain debug.log lines)
                      2160    // * estimated number of transactions per day after checkpoint
       };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v1)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = -1;
        consensus.nMasternodePaymentsStartBlock = 121;
        consensus.nMasternodePaymentsIncreaseBlock = -1;
        consensus.nMasternodePaymentsIncreasePeriod = -1;
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 2282;
        consensus.nBudgetPaymentsCycleBlocks = 90;
        consensus.nBudgetPaymentsWindowBlocks = 39;
        consensus.nBudgetProposalEstablishingTime = 720;
        consensus.nSuperblockStartBlock = 2432;
        consensus.nSuperblockCycle = 90;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;

        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;

        consensus.nMajorityWindow = 390;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256S("0x0");
        consensus.powLimit = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 60;
        consensus.nPowTargetSpacing = 40;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 8;
        consensus.nMinerConfirmationWindow = 11;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

          pchMessageStart[0] = 0xff;
          pchMessageStart[1] = 0xfe;
          pchMessageStart[2] = 0xff;
          pchMessageStart[3] = 0xc2;

        vAlertPubKey = ParseHex("0446a60b89dcabfce423350a32b177199622991a5e19adaec943c835e8d83cc07c346d5e62cb3bf3b518e25fe2d051fd794956e0686b357a32bbdb542e84b1b6c7");
        nDefaultPort = 18683;
        nMaxTipAge = 0x7fffffff;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1500179697, 721030, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000039be1722d59dee156d87213e84e114bdb08b643dd3c2b0c979cc2506d55"));
        assert(genesis.hashMerkleRoot == uint256S("0xaa920cef2c0994e0480c2525054d150477eb779e5e774ae88961a80999378a08"));

        vFixedSeeds.clear();
        vSeeds.clear();

	vSeeds.push_back(CDNSSeedData("159.203.109.115","159.203.109.115"));



        // MonetaryUnit addresses start with 'G'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        // MonetaryUnit script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // MonetaryUnit private keys start with 'S' or 'T'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,64);

        // Testnet MonetaryUnit BIP32 pubkeys
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet MonetaryUnit BIP32 prvkeys
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        // Testnet MonetaryUnit BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60;
        strSporkPubKey = "04251df9125d968a5efeac89f08be613621ae19d3d9ca4818485d2405a994b6164d9f26c5ad3e7a19a99dc36fa7dd03f05e968b4bdd1dc39e5b25c0dc60a441506";
        strMasternodePaymentsPubKey = "0483bbc11d4c6a0cb4361da2a234912a7e174e2b9ecfb7685920c24a58fa32205d73f272540032ec7f4dd9d7d865bf171268dcacaa1184675cb2ed2361eb93218f";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("0x0")),

            1483076495, // * UNIX timestamp of last checkpoint block
            168590,     // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            500         // * estimated number of transactions per day after checkpoint
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = -1;
        consensus.nMasternodePaymentsStartBlock = 121;
        consensus.nMasternodePaymentsIncreaseBlock = -1;
        consensus.nMasternodePaymentsIncreasePeriod = -1;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 212;
        consensus.nBudgetPaymentsCycleBlocks = 90;
        consensus.nBudgetPaymentsWindowBlocks = 39;
        consensus.nBudgetProposalEstablishingTime = 720;
        consensus.nSuperblockStartBlock = 318;
        consensus.nSuperblockCycle = 10;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 100;
        consensus.nMasternodeMinimumConfirmations = 1;

        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;

        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256S("0x0");
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60;
        consensus.nPowTargetSpacing = 40;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108;
        consensus.nMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

          pchMessageStart[0] = 0xff;
          pchMessageStart[1] = 0xfe;
          pchMessageStart[2] = 0xff;
          pchMessageStart[3] = 0xc1;

        nMaxTipAge = 1 * 60 * 60;
        nDefaultPort = 17683;
        nPruneAfterHeight = 1000;


        genesis = CreateGenesisBlock(1500179697, 721030, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000039be1722d59dee156d87213e84e114bdb08b643dd3c2b0c979cc2506d55"));
        assert(genesis.hashMerkleRoot == uint256S("0xaa920cef2c0994e0480c2525054d150477eb779e5e774ae88961a80999378a08"));

        vFixedSeeds.clear();
        vSeeds.clear();

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        nFulfilledRequestExpireTime = 5*60;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x0")),
            0,
            0,
            0
        };

        // MonetaryUnit addresses start with 'R'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,61);
        // MonetaryUnit script addresses start with 'U' or 'V'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,69);
        // MonetaryUnit private keys start with 'Q' or 'R'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,59);

        // Regtest MonetaryUnit BIP32 pubkeys start with
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Regtest MonetaryUnit BIP32 prvkeys start with
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        // Regtest MonetaryUnit BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();
   }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}
