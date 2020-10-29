package mpctestclient;

import java.math.BigInteger;

/**
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class MPCTestClient {


    /**
     * The main method that runs the demo
     *
     * @param args are ignored
     */
    public static void main(String[] args) throws Exception {

        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.testCardType = MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL;
        runCfg.numPlayers = 5;
        runCfg.numWholeTestRepeats = 1;
        runCfg.cardName = "gd60";

        MPCRunDemo(runCfg);

    }

    public static void MPCRunDemo(MPCRunConfig runConfig) throws Exception {
        MPCRun mpcRun = new MPCRun(runConfig);

        mpcRun.connectAll();

        for (int i = 0; i < runConfig.numWholeTestRepeats; i++) {

            mpcRun.getCardInfoAll();

            mpcRun.performSetupAll(mpcRun.hostFullPriv);

            mpcRun.performKeyGen(mpcRun.hostKeyGen);

            mpcRun.performEncryptDecrypt(BigInteger.TEN, mpcRun.hostDecryptSign);

            mpcRun.signCacheAll(mpcRun.hostDecryptSign);

            mpcRun.performSignature(BigInteger.TEN, mpcRun.hostDecryptSign);

            mpcRun.generateRandomAll(87, mpcRun.hostFullPriv);

            mpcRun.resetAll(mpcRun.hostQuorumManag);
        }

        mpcRun.disconnectAll();

    }


    /**
     * Protocol test template that tests if players respond correctly to requests submitted
     * by hosts that don't have sufficient privileges
     *
     * @param mpcRunConfig protocol run configuration
     * @throws Exception
     */
    public static void InsufficientPrivilegesRun(MPCRunConfig mpcRunConfig) throws Exception {
        MPCRun mpcRun = new MPCRun(mpcRunConfig);

        mpcRun.connectAll();

        mpcRun.performSetupAll(mpcRun.hostFullPriv);


        for (MPCPlayer player : mpcRun.players) {
            try {
                mpcRun.keyGen(player, mpcRun.hostDecryptSign);
                assert (false);
            } catch (HostNotAllowedException ignored) {
            }

            mpcRun.keyGen(player, mpcRun.hostKeyGen);

            try {
                mpcRun.retrieveHash(player, mpcRun.hostDecryptSign);
                assert (false);
            } catch (HostNotAllowedException ignored) {
            }

            mpcRun.retrieveHash(player, mpcRun.hostKeyGen);
        }

        for (MPCPlayer player : mpcRun.players) {

            try {
                mpcRun.storePubKeyHash(player, player, mpcRun.hostQuorumManag);
                assert (false);
            } catch (HostNotAllowedException ignored) {
            }
        }
        mpcRun.storePubKeyHashAll(mpcRun.hostKeyGen);

        for (MPCPlayer player : mpcRun.players) {
            try {
                mpcRun.retrievePubKey(player, mpcRun.hostDecryptSign);
                assert (false);
            } catch (HostNotAllowedException ignored) {
            }
            mpcRun.retrievePubKey(player, mpcRun.hostKeyGen);
        }
        for (MPCPlayer player : mpcRun.players) {
            try {

                mpcRun.storePubKey(player, player, mpcRun.hostDecryptSign);
                assert (false);
            } catch (HostNotAllowedException ignored) {
            }
        }
        mpcRun.storePubKeyAll(mpcRun.hostKeyGen);
        for (MPCPlayer player : mpcRun.players) {
            try {

                mpcRun.retrieveYagg(player, mpcRun.hostDecryptSign);
                assert (false);
            } catch (HostNotAllowedException ignored) {
            }
            mpcRun.retrieveYagg(player, mpcRun.hostKeyGen);
        }

        byte[] ciphertext;
        try {
            ciphertext = mpcRun.encrypt(BigInteger.TEN, mpcRun.hostKeyGen);
            assert (false);
        } catch (HostNotAllowedException ignored) {
        }

        ciphertext = mpcRun.encrypt(BigInteger.TEN, mpcRun.hostFullPriv);

        for (MPCPlayer player : mpcRun.players) {
            try {
                mpcRun.decrypt(player, ciphertext, mpcRun.hostQuorumManag);
                assert (false);
            } catch (HostNotAllowedException ignored) {
            }
        }

        for (MPCPlayer player : mpcRun.players) {
            try {
                mpcRun.generateRandom(player, 47, mpcRun.hostKeyGen);
                assert (false);
            } catch (HostNotAllowedException ignored) {
            }

        }


        for (MPCPlayer player : mpcRun.players) {
            try {
                mpcRun.reset(player, mpcRun.hostKeyGen);
                assert (false);
            } catch (HostNotAllowedException ignored) {
            }
        }

        mpcRun.resetAll(mpcRun.hostQuorumManag);

        mpcRun.disconnectAll();
    }

}
