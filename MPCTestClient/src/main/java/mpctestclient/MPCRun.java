package mpctestclient;


import mpc.Consts;
import mpc.HostACL;
import org.bouncycastle.math.ec.ECPoint;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;


/**
 * The {@link MPCRun} class provides a higher layer on top
 * of the {@link MPCPlayer} interface. It provides methods
 * for a protocol run that make using and testing the protocol
 * easier and allow performance testing.
 */
//TODO: Use a logger instead of System.out.println()
//TODO: Finish documentation
public class MPCRun {

    public static String format = "%-40s:%s%n\n-------------------------------------------------------------------------------\n";
    static byte[] MPC_APPLET_AID = {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x0a, (byte) 0x4d,
            (byte) 0x50, (byte) 0x43, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6c, (byte) 0x65, (byte) 0x74, (byte) 0x31};
    public short QUORUM_INDEX = 0;
    public MPCRunConfig runCfg;

    // Protocol run specific parameters
    public ArrayList<CardChannel> cardsList;
    public ArrayList<MPCPlayer> players = new ArrayList<>();

    // Hosts
    public Host hostFullPriv;
    public Host hostKeyGen;
    public Host hostQuorumManag;
    public Host hostDecryptSign;
    public ArrayList<Host> hosts;

    // Crypto-objects
    MPCGlobals mpcGlobals = new MPCGlobals();

    // Performance testing variables
    Long m_lastTransmitTime = 0L;
    Long combinedTime = 0L;
    Long combinedTimeDecrypt = 0L;
    PerfLogger perfLogger;


    public MPCRun(MPCRunConfig runConfig) throws Exception {
        this.runCfg = runConfig;

        String experimentID = String.format("%d", System.currentTimeMillis());
        perfLogger = new PerfLogger(new FileOutputStream(String.format("MPC_DETAILPERF_log_%s.csv", experimentID)));

        mpcGlobals.Rands = new ECPoint[runCfg.numPlayers];
        players.clear();

        setupHosts();
    }


    /**
     * Connects to all available cards and simulates the remaining players.
     *
     * @throws CardException
     * @throws NoSuchAlgorithmException
     * @throws MPCException
     */
    public void connectAll() throws CardException, NoSuchAlgorithmException, MPCException {

        System.out.print("Connecting to MPC cards...");
        cardsList = new ArrayList<>();
        CardChannel connChannel = CardManagement.Connect(runCfg);

        if (runCfg.testCardType == MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL) {
            cardsList.add(connChannel);
        }

        short cardID = runCfg.thisCardID;

        for (CardChannel channel : cardsList) {
            CardMPCPlayer cardPlayer = new CardMPCPlayer(channel, m_lastTransmitTime, mpcGlobals);

            players.add(cardPlayer);
            cardID++;
        }

        System.out.println(" Done.");

        // Simulate all remaining participants in protocol in addition to MPC card(s)
        for (; cardID < runCfg.numPlayers; cardID++) {
            players.add(new SimulatedMPCPlayer(mpcGlobals));
        }
    }


    /**
     * Sends a request to generate a key-pair.
     *
     * @param player that the request will be sent to
     * @param host   that submitted the request
     * @throws Exception
     */
    public void keyGen(MPCPlayer player, Host host) throws Exception {
        String operationName = "Generate KeyPair (INS_KEYGEN_INIT)";
        System.out.format(format, operationName, player.GenKeyPair(QUORUM_INDEX, host.host_id, host.privateKeyObject));
        perfLogger.writePerfLog(operationName, m_lastTransmitTime);
        combinedTime += m_lastTransmitTime;
    }

    /**
     * Sends requests to generate a key-pair to all players.
     *
     * @param host that submitted the request
     * @throws Exception
     */
    public void keyGenAll(Host host) throws Exception {
        for (MPCPlayer player : players) {
            keyGen(player, host);
        }
    }

    /**
     * Sends a request to retrieve the hash of player's public key
     *
     * @param player that the request will be sent to
     * @param host   that submitted the request
     * @throws Exception
     */
    public void retrieveHash(MPCPlayer player, Host host) throws Exception {
        String operationName = "Retrieve Hash of pub key (INS_KEYGEN_RETRIEVE_HASH)";
        System.out.format(format, operationName, player.RetrievePubKeyHash(QUORUM_INDEX, host.host_id, host.privateKeyObject));
        perfLogger.writePerfLog(operationName, m_lastTransmitTime);
        combinedTime += m_lastTransmitTime;
    }

    public ECPoint getYagg() {
        return mpcGlobals.AggPubKey;
    }

    /**
     * Sends requests to retrieve hashes of players' public keys to all cards
     *
     * @param host that submitted the request
     * @throws Exception
     */
    public void retrieveHashAll(Host host) throws Exception {
        for (MPCPlayer player : players) {
            retrieveHash(player, host);
        }
    }

    /**
     * Stores hash of the source player's public key to the target player.
     *
     * @param playerSource player whose public key hash will be stored
     * @param playerTarget player that will store the hash
     * @param host         that submitted the request
     * @throws Exception
     */
    public void storePubKeyHash(MPCPlayer playerSource, MPCPlayer playerTarget, Host host) throws Exception {
        String operationName = "Store pub key hash (INS_KEYGEN_STORE_HASH)";
        System.out.format(format, operationName, playerTarget.StorePubKeyHash(QUORUM_INDEX, playerSource.GetPlayerIndex(QUORUM_INDEX), playerSource.GetPubKeyHash(QUORUM_INDEX), host.host_id, host.privateKeyObject));
        perfLogger.writePerfLog(operationName, m_lastTransmitTime);
        combinedTime += m_lastTransmitTime;
    }

    /**
     * Sends requests to store hashes of all players to all players.
     *
     * @param host that submitted the request
     * @throws Exception
     */
    public void storePubKeyHashAll(Host host) throws Exception {
        for (MPCPlayer playerTarget : players) {
            for (MPCPlayer playerSource : players) {
                if (playerTarget != playerSource) {
                    storePubKeyHash(playerSource, playerTarget, host);
                }
            }
        }
    }

    /**
     * Sends a request to retrieve the player's public key
     *
     * @param player that the request will be sent to
     * @param host   that submitted the request
     * @return the public key as an ECpoint
     * @throws Exception
     */
    public ECPoint retrievePubKey(MPCPlayer player, Host host) throws Exception {
        String operationName = "Retrieve Pub Key (INS_KEYGEN_RETRIEVE_PUBKEY)";
        ECPoint pub_share_EC = Util.ECPointDeSerialization(mpcGlobals.curve, player.RetrievePubKey(QUORUM_INDEX, host.host_id, host.privateKeyObject, mpcGlobals), 0);
        System.out.format(format, operationName, Util.bytesToHex(pub_share_EC.getEncoded(false)));
        perfLogger.writePerfLog(operationName, m_lastTransmitTime);
        combinedTime += m_lastTransmitTime;
        return pub_share_EC;
    }

    /**
     * Sends requests to retrieve public key to all players
     *
     * @param host that submitted the request
     * @throws Exception
     */
    public void retrievePubKeyAll(Host host) throws Exception {
        for (MPCPlayer player : players) {
            retrievePubKey(player, host);
        }
    }

    /**
     * Sends a request to store the source player's public key to target player
     *
     * @param playerSource source player
     * @param playerTarget target player
     * @param host         that submitted the request
     * @throws Exception
     */
    public void storePubKey(MPCPlayer playerSource, MPCPlayer playerTarget, Host host) throws Exception {
        String operationName = "Store Pub Key (INS_KEYGEN_STORE_PUBKEY)";
        System.out.format(format, operationName, playerTarget.StorePubKey(QUORUM_INDEX, playerSource.GetPlayerIndex(QUORUM_INDEX),
                playerSource.GetPubKey(QUORUM_INDEX).getEncoded(false), host.host_id, host.privateKeyObject));
        perfLogger.writePerfLog(operationName, m_lastTransmitTime);
        combinedTime += m_lastTransmitTime;
    }

    /**
     * Sends requests to store public keys to all players
     *
     * @param host that submitted the request
     * @throws Exception
     */
    public void storePubKeyAll(Host host) throws Exception {
        for (MPCPlayer playerTarget : players) {
            for (MPCPlayer playerSource : players) {
                if (playerTarget != playerSource) {
                    storePubKey(playerSource, playerTarget, host);
                }
            }
        }
    }


    /**
     * Sends a request to retrieve the aggregated key
     *
     * @param player that the request will be sent to
     * @param host   that submitted the request
     * @throws Exception
     */
    public void retrieveYagg(MPCPlayer player, Host host) throws Exception {
        String operationName = "Retrieve Aggregated Key (INS_KEYGEN_RETRIEVE_AGG_PUBKEY)";
        System.out.format(format, operationName, player.RetrieveAggPubKey(QUORUM_INDEX, host.host_id, host.privateKeyObject));

        perfLogger.writePerfLog(operationName, m_lastTransmitTime);
        combinedTime += m_lastTransmitTime;
    }

    /**
     * Sends requests to retrieve the aggregated key to all players
     *
     * @param host that submitted the request
     * @throws Exception
     */
    public void retrieveYaggAll(Host host) throws Exception {
        boolean isFirstPlayer = true;

        for (MPCPlayer player : players) {
            retrieveYagg(player, host);

            if (isFirstPlayer) {
                mpcGlobals.AggPubKey = player.GetAggregatedPubKey(QUORUM_INDEX);
            }
            isFirstPlayer = false;
        }
    }

    /**
     * Higher level function, performs the whole key-generation
     * and distribution part of the protocol.
     *
     * @throws Exception if generation fails
     */
    public void performKeyGen(Host host) throws Exception {
        combinedTime = (long) 0;

        keyGenAll(host);

        retrieveHashAll(host);

        storePubKeyHashAll(host);

        retrievePubKeyAll(host);

        storePubKeyAll(host);

        retrieveYaggAll(host);
    }


    /**
     * Creates hosts that are later used for submitting requests
     *
     * @throws Exception
     */
    private void setupHosts() throws Exception {
        hostFullPriv = new Host(new short[]{HostACL.ACL_FULL_PRIVILEGES}, mpcGlobals);
        hostKeyGen = new Host(new short[]{HostACL.ACL_KEY_GENERATION}, mpcGlobals);
        hostQuorumManag = new Host(new short[]{HostACL.ACL_QUORUM_MANAGEMENT}, mpcGlobals);
        hostDecryptSign = new Host(new short[]{HostACL.ACL_DECRYPT, HostACL.ACL_ENCRYPT, HostACL.ACL_SIGN}, mpcGlobals);
        hosts = new ArrayList<>(Arrays.asList(hostFullPriv, hostKeyGen, hostQuorumManag, hostDecryptSign));

    }


    /**
     * Sends requests to retrieve information about a card.
     * (Currently implemented only in {@link mpc.MPCApplet}
     *
     * @throws Exception
     */
    public void getCardInfoAll() throws Exception {
        for (MPCPlayer player : players) {
            if (player instanceof CardMPCPlayer) {
                ((CardMPCPlayer) player).GetCardInfo();
            }
        }
    }


    /**
     * Sends a request to reset a player
     *
     * @param player to reset
     * @param host   that submitted the request
     * @throws Exception
     */
    public void reset(MPCPlayer player, Host host) throws Exception {
        String operationName = "Reseting the card to an uninitialized state (INS_RESET)";
        System.out.format(format, operationName, player.Reset(QUORUM_INDEX, host.host_id, host.privateKeyObject));
        perfLogger.writePerfLog(operationName, m_lastTransmitTime);
    }

    /**
     * Sends requests to reset to all players
     *
     * @param host that submitted the request
     * @throws Exception
     */
    public void resetAll(Host host) throws Exception {
        for (MPCPlayer player : players) {
            reset(player, host);
        }
    }

    /**
     * Sends a request to set up a player
     *
     * @param player      that will receive the request
     * @param playerIndex index of a player - players identify other players by indices
     * @param host        that submitted the request
     * @throws Exception
     */
    public void setup(MPCPlayer player, short playerIndex, Host host) throws Exception {
        String operationName = "Setting Up the MPC Parameters (INS_SETUP)";
        System.out.format(format, operationName, player.Setup(QUORUM_INDEX, runCfg.numPlayers, playerIndex, host.host_id, host.privateKeyObject));
        perfLogger.writePerfLog(operationName, m_lastTransmitTime);
    }

    /**
     * Sends requests to set up to all players
     *
     * @param host that submitted the request
     * @throws Exception
     */
    public void setupAll(Host host) throws Exception {
        short playerIndex = 0;
        for (MPCPlayer player : players) {
            setup(player, playerIndex, host);
            playerIndex += 1;
        }
    }

    /**
     * Sends hosts' public keys to be stored to a single player.
     *
     * @param player that will receive public keys
     * @param host that submitted this request
     * @throws Exception
     */
    public void storeHostPubKeys(MPCPlayer player, Host host) throws Exception {
        for (Host hostToStore : hosts) {
            String operationName = "Set the host's authorisation pubkey (INS_PERSONALIZE_SET_USER_AUTH_PUBKEY)";
            System.out.format(format, operationName, player.SetHostAuthPubkey(hostToStore.publicKey, hostToStore.permissions,
                    QUORUM_INDEX, host.host_id, host.privateKeyObject));
            perfLogger.writePerfLog(operationName, m_lastTransmitTime);
        }
    }

    /**
     * Sends hosts' public keys to be stored to all players.
     *
     * @param host that submitted this request
     * @throws Exception
     */
    public void storeHostPubKeysAll(Host host) throws Exception {
        for (MPCPlayer player : players) {
            storeHostPubKeys(player, host);
        }
    }

    /**
     * Sends a request to remove quorum to a single player
     * @param player that will receive the request
     * @param host that submitted the request
     * @throws Exception
     */
    public void remove(MPCPlayer player, Host host) throws Exception {
        String operationName = "Removing quorum (INS_QUORUM_RESET)";
        System.out.format(format, operationName, player.Remove(QUORUM_INDEX, host.host_id, host.privateKeyObject));
        perfLogger.writePerfLog(operationName, m_lastTransmitTime);
    }

    public void removeAll(Host host) throws Exception {
        for (MPCPlayer player : players) {
            remove(player, host);
        }
    }

    /**
     * Setups all players and stores hosts' public keys
     * @param host that submitted the request
     * @throws Exception
     */
    public void performSetupAll(Host host) throws Exception {

        short playerIndex = 0;
        for (MPCPlayer player : players) {

            reset(player, host);

            setup(player, playerIndex, host);

            storeHostPubKeys(player, host);

            playerIndex++;
        }
    }

    /**
     * Sends a disconnect request to a single player
     * @param player that will receive the request
     * @throws IOException
     */
    public void disconnect(MPCPlayer player) throws IOException {
        String operationName = "Disconnecting from a player: ";
        player.disconnect();
        System.out.format(format, operationName, true);
        perfLogger.writePerfLog(operationName, m_lastTransmitTime);
    }

    /**
     * Sends a disconnect request to all players
     * @throws IOException
     */
    public void disconnectAll() throws IOException {
        for (MPCPlayer player : players) {
            disconnect(player);
        }
    }

    /**
     * Sends a request for encryption to the first player.
     * @param message message to be encrypted
     * @param host that submitted the request
     * @return ciphertext
     * @throws Exception
     */
    public byte[] encrypt(BigInteger message, Host host) throws Exception {
        String operationName;
        Long combinedTime = (long) 0;

        MPCPlayer player = players.get(0);
        byte[] plaintext = mpcGlobals.G.multiply(message).getEncoded(false);
        operationName = String.format("Encrypt(%s) (INS_ENCRYPT)", message.toString());

        byte[] ciphertext = player.Encrypt(QUORUM_INDEX, plaintext, host.host_id, host.privateKeyObject);
        perfLogger.writePerfLog(operationName, m_lastTransmitTime);
        combinedTime += m_lastTransmitTime;


        combinedTimeDecrypt = combinedTime - m_lastTransmitTime; // Remove encryption time from combined decryption time
        perfLogger.writePerfLog("* Combined Encrypt time", combinedTime);
        return ciphertext;
    }


    /**
     * Sends a request for decryption to a single player
     * @param player that will receive the request
     * @param ciphertext to be decrypted
     * @param host that submitted this request
     * @return decrypt share
     * @throws Exception
     */
    public ECPoint decrypt(MPCPlayer player, byte[] ciphertext, Host host) throws Exception {

        String operationName = "Decrypt (INS_DECRYPT)";
        byte[] xc1_share = player.Decrypt(QUORUM_INDEX, ciphertext, host.host_id, host.privateKeyObject);
        ECPoint xc1_EC = Util.ECPointDeSerialization(mpcGlobals.curve, xc1_share, 0);

        perfLogger.writePerfLog(operationName, m_lastTransmitTime);
        combinedTime += m_lastTransmitTime;
        combinedTimeDecrypt += m_lastTransmitTime;

        perfLogger.perfResults.add(new AbstractMap.SimpleEntry<>("* Combined Decrypt time", combinedTimeDecrypt));
        perfLogger.writePerfLog("* Combined Decrypt time", combinedTimeDecrypt);
        return xc1_EC;
    }

    /**
     * Sends requests for decryption to all players and combines theirs share.
     *
     * @param ciphertext to be decrypted
     * @param host that submitted this request
     * @return plaintext
     * @throws Exception
     */
    public ECPoint decryptAll(byte[] ciphertext, Host host) throws Exception {
        ECPoint c2 = Util.ECPointDeSerialization(mpcGlobals.curve, ciphertext, Consts.SHARE_DOUBLE_SIZE_CARRY);

        // Combine all decryption shares (x_ic) (except for card which is added below)
        ECPoint xc1_EC = mpcGlobals.curve.getInfinity();
        for (MPCPlayer player : players) {
            xc1_EC = xc1_EC.add(decrypt(player, ciphertext, host).negate());
        }

        return c2.add(xc1_EC);
    }

    /**
     * Test on encryption/decryption
     *
     * @param msgToEncDec message as a BigInteger
     * @throws Exception if encryption/decryption fails
     */
    void performEncryptDecrypt(BigInteger msgToEncDec, Host host) throws Exception {

        byte[] ciphertext = encrypt(msgToEncDec, host);

        byte[] plaintext = mpcGlobals.G.multiply(msgToEncDec).getEncoded(false);


        ECPoint plaintext_EC = decryptAll(ciphertext, host);

        System.out.format(format, "Decryption successful?:",
                Arrays.equals(plaintext, plaintext_EC.getEncoded(false)));

        assert (Arrays.equals(plaintext, plaintext_EC.getEncoded(false)));

    }

    /**
     * Sends a request for caching Rij to a single player.
     * @param player that will receive the request
     * @param host that submitted this request
     * @throws Exception
     */
    public void signCache(MPCPlayer player, Host host) throws Exception {
        for (short round = 1; round <= mpcGlobals.Rands.length; round++) {
            if (mpcGlobals.Rands[round - 1] == null) {
                mpcGlobals.Rands[round - 1] = Util.ECPointDeSerialization(mpcGlobals.curve, player.Gen_Rin(QUORUM_INDEX, round, host.host_id, host.privateKeyObject), 0);
            } else {
                mpcGlobals.Rands[round - 1] = mpcGlobals.Rands[round - 1].add(Util.ECPointDeSerialization(mpcGlobals.curve, player.Gen_Rin(QUORUM_INDEX, round, host.host_id, host.privateKeyObject), 0));
            }
        }
    }

    /**
     * Subsequently, the host uses Algorithm 4.3 to compute the aggregate (Rj)
     * of the group elements (Algorithm 4.3) received from the ICs for a
     * particular j, and stores it for future use
     *
     * @throws Exception if generation fails
     */
    public void signCacheAll(Host host) throws Exception {

        Arrays.fill(mpcGlobals.Rands, null);

        for (MPCPlayer player : players) {
            signCache(player, host);
        }

        for (int round = 1; round <= mpcGlobals.Rands.length; round++) {
            System.out.format("Rands[%d]%s\n", round - 1, Util.bytesToHex(mpcGlobals.Rands[round - 1].getEncoded(false)));
        }
        System.out.println();
    }

    /**
     * Sends a sign request to a single player
     * @param player that will receive the request
     * @param host that submitted this request
     * @param plaintext to be signed
     * @param counter signature counter
     * @return signature
     * @throws Exception
     */
    public BigInteger sign(MPCPlayer player, Host host, byte[] plaintext, int counter) throws Exception {
        return player.Sign(QUORUM_INDEX, counter, mpcGlobals.Rands[counter - 1].getEncoded(false), plaintext, host.host_id, host.privateKeyObject);
    }

    /**
     * Sends sign requests to all players and combines theirs shares
     * @param msgToSign message to be signed
     * @param host that submitted this request
     * @return signature s
     * @throws Exception
     */
    public BigInteger signAll(BigInteger msgToSign, Host host) throws Exception {
        byte[] plaintext_sig = mpcGlobals.G.multiply(msgToSign).getEncoded(false);
        int counter = 1;

        BigInteger sum_s_BI = null;

        for (MPCPlayer player : players) {
            if (sum_s_BI == null) {
                counter = player.GetCurrentCounter(QUORUM_INDEX, host.host_id, host.privateKeyObject).intValue() + 1;
                sum_s_BI = sign(player, host, plaintext_sig, counter);
            } else {
                sum_s_BI = sum_s_BI.add(sign(player, host, plaintext_sig, counter));
                sum_s_BI = sum_s_BI.mod(mpcGlobals.n);
            }
        }
        return sum_s_BI;
    }


    /**
     * Host has collected all the shares for the same j, can use Algorithm 4.3
     * on all the σi, j to recover σj , obtaining the aggregate signature (σj ,
     * ϵj ). The recipient of (m, j), σ, ϵ can verify the validity of the
     * signature by checking if ϵ = Hash(R| |Hash(m)| |j), where R = σ ·G +ϵ ·Y.
     *
     * @param msgToSign plaintext message
     * @throws Exception if signature fails
     */
    public void performSignature(BigInteger msgToSign, Host host) throws Exception {

        BigInteger sum_s_BI = signAll(msgToSign, host);
        byte[] plaintextSig = mpcGlobals.G.multiply(msgToSign).getEncoded(false);
        BigInteger card_e_BI = players.get(0).GetE(QUORUM_INDEX);
        String operationName = "Signature verification successful?";

        boolean verResult = verify(plaintextSig, mpcGlobals.AggPubKey, sum_s_BI, card_e_BI);
        System.out.format(format, operationName, verResult);
        assert (verResult);

    }

    /**
     * Verifies signature
     *
     * @param plaintext byte[] plaintext
     * @param pubkey    public  key used for verification
     * @param s_bi      BigInteger s
     * @param e_bi      BigInteger e
     * @return verification result
     * @throws NoSuchAlgorithmException in case message digest fails
     */
    public boolean verify(byte[] plaintext, ECPoint pubkey, BigInteger s_bi, BigInteger e_bi) throws NoSuchAlgorithmException {
        // Compute rv = sG+eY
        ECPoint rv_EC = mpcGlobals.G.multiply(s_bi); // sG
        rv_EC = rv_EC.add(pubkey.multiply(e_bi)); // +eY

        // Compute ev = H(m||rv)
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plaintext);
        md.update(rv_EC.getEncoded(false));
        byte[] ev = md.digest();
        BigInteger ev_bi = new BigInteger(1, ev);
        ev_bi = ev_bi.mod(mpcGlobals.n);
        assert (e_bi.compareTo(ev_bi) == 0);

        return e_bi.compareTo(ev_bi) == 0;
    }

    /**
     * Sends a request to generate random bytes
     *
     * @param player that will receive the request
     * @param size   number of bytes to generate
     * @param host   that submitted the request
     * @throws Exception
     */
    public void generateRandom(MPCPlayer player, int size, Host host) throws Exception {
        byte[] receivedByteArray = player.GenerateRandom(QUORUM_INDEX, host.host_id, host.privateKeyObject, (short) size);
        String operationName = "Generating random byte array(INS_GENERATE_RANDOM)";
        System.out.format(format, operationName, Util.bytesToHex(receivedByteArray) + "\nsuccessful?        :"
                + (receivedByteArray.length == size));
        assert (receivedByteArray.length == size);
    }

    /**
     * Sends requests to generate random bytes to all players.
     *
     * @param size number of bytes to generate
     * @param host that submitted the request
     * @throws Exception
     */
    public void generateRandomAll(int size, Host host) throws Exception {
        System.out.println("\nGenerate Random (" + size + "B)\n");
        for (MPCPlayer player : players) {
            generateRandom(player, size, host);

        }
    }

}
