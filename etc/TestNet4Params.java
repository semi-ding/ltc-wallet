package io.acrosafe.wallet.core.ltc;

import static com.google.common.base.Preconditions.checkState;
import org.litecoinj.core.Utils;

import org.litecoinj.params.AbstractBitcoinNetParams;
import org.litecoinj.params.TestNet2Params;

import org.litecoinj.params.TestNet3Params;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class defines litecoin TestNet4 network and block information
 *
 */
public class TestNet4Params extends AbstractBitcoinNetParams
{
    // Singleton instance
    private static TestNet4Params instance;

    /**
     * Constructs new TestNet4Params instance.
     */
    private TestNet4Params() {
        super();

        // TestNet 4
        id = "test";

        // Satoshi Secretes
        alertSigningKey = Utils.HEX.decode(
                "040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9");

        // The header bytes that identify the start of a packet on this network
        packetMagic = 0xfdd2c8f1;

        // 2.5 mins interval
        interval = INTERVAL;
        targetTimespan = TARGET_TIMESPAN;

        // Maximum target represents the easiest allowable proof of work
        maxTarget = Utils.decodeCompactBits(0x2e0ffff0);

        // Testnet port for testnet4
        port = 19335;

        // the depth of blocks required for a coinbase transaction to be spendable.
        spendableCoinbaseDepth = 100;
        subsidyDecreaseBlockCount = 210000;

        // Address header
        addrSeeds = null;
        dumpedPrivateKeyHeader = 239;
        addressHeader = 111;
        p2shHeader = 58;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };

        // Populates genesis block information
        genesisBlock.setTime(1486949366);
        genesisBlock.setDifficultyTarget(0x1e0ffff0);
        genesisBlock.setNonce(293345);

        // make sure the genesis hash is correct.
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0"));

        // DNS seeds.
        dnsSeeds =
                new String[]{"testnet-seed.litecointools.com", "seed-b.litecoin.loshan.co.uk", "dnsseed-testnet.thrasher.io"};

        majorityEnforceBlockUpgrade = TestNet2Params.TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = TestNet2Params.TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = TestNet2Params.TESTNET_MAJORITY_WINDOW;
    }

    /**
     * Returns TestNet4Params instance.
     *
     * @return
     */
    public static synchronized TestNet4Params get() {
        if (instance == null) {
            instance = new TestNet4Params();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_TESTNET;
    }


}