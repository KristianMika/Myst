package mpctestclient;

import mpc.Consts;
import mpc.HostACL;
import mpc.PM;
import mpc.jcmathlib.SecP256r1;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import javax.smartcardio.CardChannel;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class MPCTestClient {

    public final static boolean _DEBUG = true;
    public final static boolean _SIMULATOR = true;
    public final static boolean _PROFILE_PERFORMANCE = false;
    public final static boolean _FAIL_ON_ASSERT = true;
    public final static boolean _IS_BACKDOORED_EXAMPLE = false; // if true, applet is set into example "backdoored" state simulating compromised node with known key

    public final static boolean _FIXED_PLAYERS_RNG = false;

    public final static short QUORUM_INDEX = 0;
    public static final int HOST_COUNT = 2;
    //public static byte[] APDU_RESET = {(byte) 0xB0, (byte) 0x03, (byte) 0x00, (byte) 0x00};
    public static final byte[] PERF_COMMAND_NONE = {Consts.CLA_MPC, Consts.INS_PERF_SETSTOP, 0, 0, 2, 0, 0};
    public final static boolean MODIFY_SOURCE_FILES_BY_PERF = true;
    static final String PERF_TRAP_CALL = "PM.check(PM.";
    static final String PERF_TRAP_CALL_END = ");";
    public static List<HostObj> hosts;
    // Objects
    public static String format = "%-40s:%s%n\n-------------------------------------------------------------------------------\n";
    // acl of this host

    public static HashMap<Short, String> PERF_STOP_MAPPING = new HashMap<>();
    public static byte[] PERF_COMMAND = {Consts.CLA_MPC, Consts.INS_PERF_SETSTOP, 0, 0, 2, 0, 0};
    // Crypto-objects
    static MPCGlobals mpcGlobals = new MPCGlobals();
    static byte[] MPC_APPLET_AID = {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x0a, (byte) 0x4d, (byte) 0x50, (byte) 0x43, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6c, (byte) 0x65, (byte) 0x74, (byte) 0x31};
    // Performance testing variables
    static ArrayList<Map.Entry<String, Long>> perfResults = new ArrayList<>();
    static Long m_lastTransmitTime = 0L;

    // end Performance testing variables

    /**
     * The main method that runs the demo
     *
     * @param args are ignored
     */
    public static void main(String[] args) {
        try {
            buildPerfMapping();

            MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
            runCfg.testCardType = MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL;
            //runCfg.testCardType = MPCRunConfig.CARD_TYPE.PHYSICAL;
            runCfg.numSingleOpRepeats = 4;
            //runCfg.numWholeTestRepeats = 10; //more than one repeat will fail on simulator due to change of address of allocated objects, runs ok on real card
            runCfg.numPlayers = 5;
            runCfg.cardName = "gd60";


            MPCProtocol_demo(runCfg);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void writePerfLog(String operationName, Long time, ArrayList<Map.Entry<String, Long>> perfResults, FileOutputStream perfFile) throws IOException {
        perfResults.add(new AbstractMap.SimpleEntry<>(operationName, time));
        perfFile.write(String.format("%s,%d\n", operationName, time).getBytes());
        perfFile.flush();
    }

    /**
     * Method that runs the demo
     *
     * @param runCfg current test configuration
     * @throws Exception if demo fails
     */
    static void MPCProtocol_demo(MPCRunConfig runCfg) throws Exception {
        String experimentID = String.format("%d", System.currentTimeMillis());
        runCfg.perfFile = new FileOutputStream(String.format("MPC_DETAILPERF_log_%s.csv", experimentID));

        // Prepare globals
        mpcGlobals.Rands = new ECPoint[runCfg.numPlayers];
        mpcGlobals.players.clear();

        // Prepare SecP256r1 curve
        prepareECCurve(mpcGlobals);

        // Create list of hosts and grant them privileges
        hosts = new ArrayList<HostObj>();
        hosts.add(new HostObj(new short[]{HostACL.ACL_FULL_PRIVILEGES}));
        hosts.add(new HostObj(new short[]{HostACL.ACL_KEY_GENERATION}));

        // Obtain list of all connected MPC cards
        System.out.print("Connecting to MPC cards...");
        ArrayList<CardChannel> cardsList = new ArrayList<>();
        CardChannel connChannel = CardManagement.Connect(runCfg);

        if (runCfg.testCardType == MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL) {
            cardsList.add(connChannel);
        }
        // Create card contexts, fill cards IDs
        short cardID = runCfg.thisCardID;
        for (CardChannel channel : cardsList) {
            CardMPCPlayer cardPlayer = new CardMPCPlayer(channel, format, m_lastTransmitTime, _FAIL_ON_ASSERT, mpcGlobals);
            // If required, make the applet "backdoored" to demonstrate functionality of incorrect behavior of a malicious attacker
            if (_IS_BACKDOORED_EXAMPLE) {
                cardPlayer.SetBackdoorExample(channel, true);
            }
            // Retrieve card information
            cardPlayer.GetCardInfo();
            mpcGlobals.players.add(cardPlayer);
            cardID++;
        }
        System.out.println(" Done.");

        // Simulate all remaining participants in protocol in addition to MPC card(s) 
        for (; cardID < runCfg.numPlayers; cardID++) {
            mpcGlobals.players.add(new SimulatedMPCPlayer(mpcGlobals));
        }

        for (int repeat = 0; repeat < runCfg.numWholeTestRepeats; repeat++) {
            perfResults.clear();
            String logFileName = String.format("MPC_PERF_log_%d.csv", System.currentTimeMillis());
            FileOutputStream perfFile = new FileOutputStream(logFileName);

            //
            // Setup card(s)
            //
            short playerIndex = 0;
            for (MPCPlayer player : mpcGlobals.players) {
                // Reset
                String operationName = "Reseting the card to an uninitialized state (INS_RESET)";
                System.out.format(format, operationName, player.Reset(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // Setup
                operationName = "Setting Up the MPC Parameters (INS_SETUP)";
                System.out.format(format, operationName, player.Setup(QUORUM_INDEX, runCfg.numPlayers, playerIndex, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // store host's pubkey
                operationName = "Set the host's authorisation pubkey (INS_PERSONALIZE_SET_USER_AUTH_PUBKEY)";
                System.out.format(format, operationName, player.SetHostAuthPubkey(hosts.get(0).publicKey, hosts.get(0).permissions,
                        QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));

                // Remove
                operationName = "Removing quorum (INS_QUORUM_RESET)";
                System.out.format(format, operationName, player.Remove(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // Reset
                operationName = "Reseting the card to an uninitialized state (INS_RESET)";
                System.out.format(format, operationName, player.Reset(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // Setup again
                operationName = "Setting Up the MPC Parameters (INS_SETUP)";
                System.out.format(format, operationName, player.Setup(QUORUM_INDEX, runCfg.numPlayers, playerIndex, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // store host's pubkey
                operationName = "Set the host's authorisation pubkey (INS_PERSONALIZE_SET_USER_AUTH_PUBKEY)";
                System.out.format(format, operationName, player.SetHostAuthPubkey(hosts.get(0).publicKey, hosts.get(0).permissions,
                        QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));

                playerIndex++;
            }

            // BUGBUG: Signature without previous EncryptDecrypt will fail on CryptoObjects.KeyPair.Getxi() - as no INS_KEYGEN_xxx was called
            PerformKeyGen(mpcGlobals.players, perfFile);

            //
            // Encrypt / Decrypt
            //
            PerformEncryptDecrypt(BigInteger.TEN, mpcGlobals.players, perfResults, perfFile);
            /*
             // Repeated measurements if required
             for (int i = 0; i < runCfg.numSingleOpRepeats; i++) {
             PerformEncryptDecrypt(BigInteger.valueOf(rng.nextInt()), players, channel, perfResults, perfFile);
             }
             */
            //
            // Sign
            //
            PerformSignCache(mpcGlobals.players, perfResults, perfFile);
            PerformSignature(BigInteger.TEN, 1, mpcGlobals.players, perfResults, perfFile, runCfg);
            /*            
             // Repeated measurements if required
             long elapsed = -System.currentTimeMillis();
             for (int i = 1; i < runCfg.numSingleOpRepeats; i++) {
             //System.out.println("******** \n RETRY " + i + " \n");
             PerformSignature(BigInteger.valueOf(rng.nextInt()), 1, players, channel, perfResults, perfFile);
             }
             elapsed += System.currentTimeMillis();
             System.out.format("Elapsed: %d ms, time per Sign = %f ms\n", elapsed,  elapsed / (float) runCfg.numSingleOpRepeats);
             */

            //
            // Generate random byte array
            //
            GenerateRandom(mpcGlobals.players, 57);

            // Reset cards
            for (MPCPlayer player : mpcGlobals.players) {
                // Reset
                String operationName = "Reseting the card to an uninitialized state (INS_RESET)";
                System.out.format(format, operationName, player.Reset(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            }

            System.out.print("Disconnecting from card...");
            for (MPCPlayer player : mpcGlobals.players) {
                player.disconnect();
            }
            System.out.println(" Done.");

            // Close cvs perf file
            perfFile.close();

            // Save performance results also as latex
            saveLatexPerfLog(perfResults);

            if (runCfg.failedPerfTraps.size() > 0) {
                System.out.println("#########################");
                System.out.println("!!! SOME PERFORMANCE TRAPS NOT REACHED !!!");
                System.out.println("#########################");
                for (String trap : runCfg.failedPerfTraps) {
                    System.out.println(trap);
                }
            } else {
                System.out.println("##########################");
                System.out.println("ALL PERFORMANCE TRAPS REACHED CORRECTLY");
                System.out.println("##########################");
            }

            // Save performance traps into single file
            String perfFileName = String.format("TRAP_RAW_%s.csv", experimentID);
            SavePerformanceResults(runCfg.perfResultsSubpartsRaw, perfFileName);

            // If required, modification of source code files is attempted
            if (MODIFY_SOURCE_FILES_BY_PERF) {
                String dirPath = "..\\!PerfSRC\\Lib\\";
                InsertPerfInfoIntoFiles(dirPath, runCfg.cardName, experimentID, runCfg.perfResultsSubpartsRaw);
            }
        }
    }

    public static void TestMPCProtocol_v20170920(MPCRunConfig runCfg, MPCRunConfig.CARD_TYPE cardType) throws Exception {
        String experimentID = String.format("%d", System.currentTimeMillis());
        runCfg.perfFile = new FileOutputStream(String.format("MPC_DETAILPERF_log_%s.csv", experimentID));

        runCfg.testCardType = cardType;
        // Prepare globals
        mpcGlobals.Rands = new ECPoint[runCfg.numPlayers];
        mpcGlobals.players.clear();

        // Prepare SecP256r1 curve
        prepareECCurve(mpcGlobals);

        // Create list of hosts and grant them privileges
        hosts = new ArrayList<HostObj>();
        hosts.add(new HostObj(new short[]{HostACL.ACL_FULL_PRIVILEGES}));
        hosts.add(new HostObj(new short[]{HostACL.ACL_KEY_GENERATION}));

        // Obtain list of all connected MPC cards
        System.out.print("Connecting to MPC cards...");
        ArrayList<CardChannel> cardsList = new ArrayList<>();
        CardChannel connChannel = CardManagement.Connect(runCfg);

        if (runCfg.testCardType == MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL) {
            cardsList.add(connChannel);
        }
        // Create card contexts, fill cards IDs
        short cardID = runCfg.thisCardID;
        for (CardChannel channel : cardsList) {
            CardMPCPlayer cardPlayer = new CardMPCPlayer(channel, format, m_lastTransmitTime, _FAIL_ON_ASSERT, mpcGlobals);
            // If required, make the applet "backdoored" to demonstrate functionality of incorrect behavior of a malicious attacker
            if (_IS_BACKDOORED_EXAMPLE) {
                cardPlayer.SetBackdoorExample(channel, true);
            }
            // Retrieve card information
            cardPlayer.GetCardInfo();
            mpcGlobals.players.add(cardPlayer);
            cardID++;
        }
        System.out.println(" Done.");

        // Simulate all remaining participants in protocol in addition to MPC card(s) 
        for (; cardID < runCfg.numPlayers; cardID++) {
            mpcGlobals.players.add(new SimulatedMPCPlayer(mpcGlobals));
        }

        for (int repeat = 0; repeat < runCfg.numWholeTestRepeats; repeat++) {
            perfResults.clear();
            String logFileName = String.format("MPC_PERF_log_%d.csv", System.currentTimeMillis());
            FileOutputStream perfFile = new FileOutputStream(logFileName);

            //
            // Setup card(s)
            //
            short playerIndex = 0;
            for (MPCPlayer player : mpcGlobals.players) {
                // Reset
                String operationName = "Reseting the card to an uninitialized state (INS_RESET)";
                System.out.format(format, operationName, player.Reset(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // Setup
                operationName = "Setting Up the MPC Parameters (INS_SETUP)";
                System.out.format(format, operationName, player.Setup(QUORUM_INDEX, runCfg.numPlayers, playerIndex, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // store hosts' pubkeys
                // list of host's permissions that will be stored in card's ACL list
                operationName = "Set the host's authorisation pubkey (INS_PERSONALIZE_SET_USER_AUTH_PUBKEY)";
                System.out.format(format, operationName, player.SetHostAuthPubkey(hosts.get(0).publicKey, hosts.get(0).permissions,
                        QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));

                // Remove
                operationName = "Removing quorum (INS_QUORUM_RESET)";
                System.out.format(format, operationName, player.Remove(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // Reset
                operationName = "Reseting the card to an uninitialized state (INS_RESET)";
                System.out.format(format, operationName, player.Reset(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // Setup again
                operationName = "Setting Up the MPC Parameters (INS_SETUP)";
                System.out.format(format, operationName, player.Setup(QUORUM_INDEX, runCfg.numPlayers, playerIndex, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // store hosts' pubkeys
                // list of host's permissions that will be stored in card's ACL list
                operationName = "Set the host's authorisation pubkey (INS_PERSONALIZE_SET_USER_AUTH_PUBKEY)";
                System.out.format(format, operationName, player.SetHostAuthPubkey(hosts.get(0).publicKey, hosts.get(0).permissions,
                        QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));

                playerIndex++;
            }

            // BUGBUG: Signature without previous EncryptDecrypt will fail on CryptoObjects.KeyPair.Getxi() - as no INS_KEYGEN_xxx was called
            PerformKeyGen(mpcGlobals.players, perfFile);

            //
            // Encrypt / Decrypt
            //
            PerformEncryptDecrypt(BigInteger.TEN, mpcGlobals.players, perfResults, perfFile);
            //
            // Sign
            //
            PerformSignCache(mpcGlobals.players, perfResults, perfFile);
            PerformSignature(BigInteger.TEN, 1, mpcGlobals.players, perfResults, perfFile, runCfg);

            //
            // Generate random byte array
            //
            GenerateRandom(mpcGlobals.players, 57);

            // Reset cards
            for (MPCPlayer player : mpcGlobals.players) {
                // Reset
                String operationName = "Reseting the card to an uninitialized state (INS_RESET)";
                System.out.format(format, operationName, player.Reset(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            }

            System.out.print("Disconnecting from card...");
            for (MPCPlayer player : mpcGlobals.players) {
                player.disconnect();
            }
            System.out.println(" Done.");

            // Close cvs perf file
            perfFile.close();
        }
    }

    static void prepareECCurve(MPCGlobals mpcParams) {
        mpcParams.p = new BigInteger(Util.bytesToHex(SecP256r1.p), 16);
        mpcParams.a = new BigInteger(Util.bytesToHex(SecP256r1.a), 16);
        mpcParams.b = new BigInteger(Util.bytesToHex(SecP256r1.b), 16);
        mpcParams.curve = new ECCurve.Fp(mpcParams.p, mpcParams.a, mpcParams.b);
        mpcParams.G = Util.ECPointDeSerialization(mpcGlobals.curve, SecP256r1.G, 0);
        mpcParams.n = new BigInteger(Util.bytesToHex(SecP256r1.r), 16); // also noted as r
        mpcParams.ecSpec = new ECParameterSpec(mpcParams.curve, mpcParams.G, mpcParams.n);
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    static void saveLatexPerfLog(ArrayList<Map.Entry<String, Long>> results) {
        try {
            // Save performance results also as latex
            String logFileName = String.format("MPC_PERF_log_%d.tex", System.currentTimeMillis());
            FileOutputStream perfFile = new FileOutputStream(logFileName);
            String tableHeader = "\\begin{tabular}{|l|c|}\n"
                    + "\\hline\n"
                    + "\\textbf{Operation} & \\textbf{Time (ms)} \\\\\n"
                    + "\\hline\n"
                    + "\\hline\n";
            perfFile.write(tableHeader.getBytes());
            for (Map.Entry<String, Long> measurement : results) {
                String operation = measurement.getKey();
                operation = operation.replace("_", "\\_");
                perfFile.write(String.format("%s & %d \\\\ \\hline\n", operation, measurement.getValue()).getBytes());
            }
            String tableFooter = "\\hline\n\\end{tabular}";
            perfFile.write(tableFooter.getBytes());
            perfFile.close();
        } catch (IOException ex) {
            Logger.getLogger(MPCTestClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Performs key generation
     *
     * @param playersList list of players that will generate their private keys
     * @param perfFile
     * @throws Exception if generation fails
     */
    static void PerformKeyGen(ArrayList<MPCPlayer> playersList, FileOutputStream perfFile) throws Exception {
        Long combinedTime = (long) 0;
        for (MPCPlayer player : playersList) {
            // Generate KeyPair in card
            String operationName = "Generate KeyPair (INS_KEYGEN_INIT)";
            System.out.format(format, operationName, player.GenKeyPair(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;

            // Retrieve Hash from card
            operationName = "Retrieve Hash of pub key (INS_KEYGEN_RETRIEVE_HASH)";
            System.out.format(format, operationName, player.RetrievePubKeyHash(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;
        }

        // Push hash for all our pub keys
        String operationName = "Store pub key hash (INS_KEYGEN_STORE_HASH)";
        for (MPCPlayer playerTarget : playersList) {
            for (MPCPlayer playerSource : playersList) {
                if (playerTarget != playerSource) {
                    System.out.format(format, operationName, playerTarget.StorePubKeyHash(QUORUM_INDEX, playerSource.GetPlayerIndex(QUORUM_INDEX), playerSource.GetPubKeyHash(QUORUM_INDEX), hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                    writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
                    combinedTime += m_lastTransmitTime;
                }
            }
        }

        // Retrieve card's Public Key
        for (MPCPlayer player : playersList) {
            operationName = "Retrieve Pub Key (INS_KEYGEN_RETRIEVE_PUBKEY)";
            ECPoint pub_share_EC = Util.ECPointDeSerialization(mpcGlobals.curve, player.RetrievePubKey(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject, mpcGlobals), 0);
            System.out.format(format, operationName, Util.bytesToHex(pub_share_EC.getEncoded(false)));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;
        }

        // Push all public keys
        operationName = "Store Pub Key (INS_KEYGEN_STORE_PUBKEY)";
        for (MPCPlayer playerTarget : playersList) {
            for (MPCPlayer playerSource : playersList) {
                if (playerTarget != playerSource) {
                    System.out.format(format, operationName, playerTarget.StorePubKey(QUORUM_INDEX, playerSource.GetPlayerIndex(QUORUM_INDEX), playerSource.GetPubKey(QUORUM_INDEX).getEncoded(false), hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                    writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
                    combinedTime += m_lastTransmitTime;
                }
            }
        }

        // Retrieve Aggregated Y
        boolean bFirstPlayer = true;
        for (MPCPlayer player : playersList) {
            operationName = "Retrieve Aggregated Key (INS_KEYGEN_RETRIEVE_AGG_PUBKEY)";
            System.out.format(format, operationName, player.RetrieveAggPubKey(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
            if (bFirstPlayer) {
                mpcGlobals.AggPubKey = player.GetAggregatedPubKey(QUORUM_INDEX);
                bFirstPlayer = false;
            }
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;
        }
    }

    /**
     * Test on encryption/decryption
     *
     * @param msgToEncDec     message as a BigInteger
     * @param playersList     list of players that will encrypt/decrypt
     * @param perfResultsList currently not used
     * @param perfFile        currently not used
     * @throws Exception if encryption/decryption fails
     */
    static void PerformEncryptDecrypt(BigInteger msgToEncDec, ArrayList<MPCPlayer> playersList, ArrayList<Map.Entry<String, Long>> perfResultsList, FileOutputStream perfFile) throws Exception {
        String operationName = "";
        Long combinedTime = (long) 0;

        // Encrypt EC Point 
        byte[] ciphertext = null;
        byte[] plaintext = null;
        if (!playersList.isEmpty()) {
            MPCPlayer player = playersList.get(0); // (only first  player == card)
            plaintext = mpcGlobals.G.multiply(msgToEncDec).getEncoded(false);
            operationName = String.format("Encrypt(%s) (INS_ENCRYPT)", msgToEncDec.toString());
            //ciphertext = player.Encrypt(QUORUM_INDEX, plaintext, runCfg, _PROFILE_PERFORMANCE);
            ciphertext = player.Encrypt(QUORUM_INDEX, plaintext, hosts.get(0).host_id, hosts.get(0).privateKeyObject);
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;
        }

        Long combinedTimeDecrypt = combinedTime - m_lastTransmitTime; // Remove encryption time from combined decryption time
        writePerfLog("* Combined Encrypt time", combinedTime, perfResults, perfFile);

        //
        // Decrypt EC Point
        //
        if (ciphertext != null && ciphertext.length > 0) {
            ECPoint c2 = Util.ECPointDeSerialization(mpcGlobals.curve, ciphertext, Consts.SHARE_DOUBLE_SIZE_CARRY);

            // Combine all decryption shares (x_ic) (except for card which is added below) 
            ECPoint xc1_EC = mpcGlobals.curve.getInfinity();
            for (MPCPlayer player : mpcGlobals.players) {
                //System.out.printf("\n");
                operationName = "Decrypt (INS_DECRYPT)";
                byte[] xc1_share = player.Decrypt(QUORUM_INDEX, ciphertext, hosts.get(0).host_id, hosts.get(0).privateKeyObject);
                xc1_EC = xc1_EC.add(Util.ECPointDeSerialization(mpcGlobals.curve, xc1_share, 0).negate()); // combine share from player

                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
                combinedTime += m_lastTransmitTime;
                combinedTimeDecrypt += m_lastTransmitTime;

                perfResultsList.add(new AbstractMap.SimpleEntry<>("* Combined Decrypt time", combinedTimeDecrypt));
                writePerfLog("* Combined Decrypt time", combinedTimeDecrypt, perfResults, perfFile);
            }

            ECPoint plaintext_EC = c2.add(xc1_EC);

            System.out.format(format, "Decryption successful?:",
                    Arrays.equals(plaintext, plaintext_EC.getEncoded(false)));
            assertIfSelected(Arrays.equals(plaintext, plaintext_EC.getEncoded(false)));
        } else {
            System.out.println("ERROR: Failed to retrieve valid encrypted block from card");
            assertIfSelected(false);
        }
    }

    /**
     * Subsequently, the host uses Algorithm 4.3 to compute the aggregate (Rj)
     * of the group elements (Algorithm 4.3) received from the ICs for a
     * particular j, and stores it for future use
     *
     * @param playersList     list of players
     * @param perfResultsList currently not used
     * @param perfFile        currently not used
     * @throws Exception if generation fails
     */
    static void PerformSignCache(ArrayList<MPCPlayer> playersList, ArrayList<Map.Entry<String, Long>> perfResultsList, FileOutputStream perfFile) throws Exception {

        for (short round = 1; round <= mpcGlobals.Rands.length; round++) {
            boolean bFirstPlayer = true;
            for (MPCPlayer player : playersList) {
                if (bFirstPlayer) {
                    mpcGlobals.Rands[round - 1] = Util.ECPointDeSerialization(mpcGlobals.curve, player.Gen_Rin(QUORUM_INDEX, round, hosts.get(0).host_id, hosts.get(0).privateKeyObject), 0);
                    bFirstPlayer = false;
                } else {
                    mpcGlobals.Rands[round - 1] = mpcGlobals.Rands[round - 1].add(Util.ECPointDeSerialization(mpcGlobals.curve, player.Gen_Rin(QUORUM_INDEX, round, hosts.get(0).host_id, hosts.get(0).privateKeyObject), 0));
                }
            }
        }
        for (int round = 1; round <= mpcGlobals.Rands.length; round++) {
            System.out.format("Rands[%d]%s\n", round - 1, Util.bytesToHex(mpcGlobals.Rands[round - 1].getEncoded(false)));
        }
        System.out.println();
    }

    /**
     * Host has collected all the shares for the same j, can use Algorithm 4.3
     * on all the σi, j to recover σj , obtaining the aggregate signature (σj ,
     * ϵj ). The recipient of (m, j), σ, ϵ can verify the validity of the
     * signature by checking if ϵ = Hash(R| |Hash(m)| |j), where R = σ ·G +ϵ ·Y.
     *
     * @param msgToSign       plaintext message
     * @param playersList     list of players that sign the message
     * @param perfResultsList currently not used
     * @param perfFile        currently not used
     * @throws Exception if signature fails
     */
    static void PerformSignature(BigInteger msgToSign, int counter, ArrayList<MPCPlayer> playersList, ArrayList<Map.Entry<String, Long>> perfResultsList, FileOutputStream perfFile, MPCRunConfig runCfg) throws Exception {
        // Sign EC Point
        byte[] plaintext_sig = mpcGlobals.G.multiply(msgToSign).getEncoded(false);

        if (!playersList.isEmpty()) {
            BigInteger sum_s_BI = new BigInteger("0");
            BigInteger card_e_BI = new BigInteger("0");
            boolean bFirstPlayer = true;
            for (MPCPlayer player : playersList) {
                if (bFirstPlayer) {
                    sum_s_BI = player.Sign(QUORUM_INDEX, counter, mpcGlobals.Rands[counter - 1].getEncoded(false), plaintext_sig, hosts.get(0).host_id, hosts.get(0).privateKeyObject);
                    card_e_BI = player.GetE(QUORUM_INDEX);
                    bFirstPlayer = false;
                } else {
                    sum_s_BI = sum_s_BI.add(player.Sign(QUORUM_INDEX, counter, mpcGlobals.Rands[counter - 1].getEncoded(false), plaintext_sig, hosts.get(0).host_id, hosts.get(0).privateKeyObject));
                    sum_s_BI = sum_s_BI.mod(mpcGlobals.n);
                }
            }
            System.out.println(String.format("Sign: %s", Util.bytesToHex(sum_s_BI.toByteArray())));

            //
            //Verification
            //
            System.out.println();
            String operationName = "Signature verification successful?";

            System.out.format(format, operationName, Verify(plaintext_sig, mpcGlobals.AggPubKey, sum_s_BI, card_e_BI));
        }
    }

    /**
     * Verification test
     *
     * @param plaintext byte[] plaintext
     * @param pubkey    public  key used for verification
     * @param s_bi      BigInteger s
     * @param e_bi      BigInteger e
     * @return verification result
     * @throws NoSuchAlgorithmException in case message digest fails
     */
    private static boolean Verify(byte[] plaintext, ECPoint pubkey, BigInteger s_bi, BigInteger e_bi) throws NoSuchAlgorithmException {
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
        //System.out.println(Util.bytesToHex(e_bi.toByteArray()));		
        //System.out.println(Util.bytesToHex(ev_bi.toByteArray()));
        assertIfSelected(e_bi.compareTo(ev_bi) == 0);

        // compare ev with e
        return e_bi.compareTo(ev_bi) == 0;
    }

    public static boolean GenerateRandom(ArrayList<MPCPlayer> playersList, int size) throws Exception {
        System.out.println("\nGenerate Random (" + size + "B)\n");
        for (MPCPlayer player : playersList) {

            byte[] receivedByteArray = player.GenerateRandom(QUORUM_INDEX, hosts.get(0).host_id, hosts.get(0).privateKeyObject, (short) size);
            String operationName = "Generating random byte array(INS_GENERATE_RANDOM)";
            System.out.format(format, operationName, Util.bytesToHex(receivedByteArray) + "\nsuccessful?        :"
                    + (receivedByteArray.length == size));
            assertIfSelected(receivedByteArray.length == size);
        }
        return true;
    }


    public static byte[] SerializeBigInteger(BigInteger BigInt) {

        int bnlen = BigInt.bitLength() / 8;

        byte[] large_int_b = new byte[bnlen];
        Arrays.fill(large_int_b, (byte) 0);
        int int_len = BigInt.toByteArray().length;
        if (int_len == bnlen) {
            large_int_b = BigInt.toByteArray();
        } else if (int_len > bnlen) {
            large_int_b = Arrays.copyOfRange(BigInt.toByteArray(), int_len
                    - bnlen, int_len);
        } else if (int_len < bnlen) {
            System.arraycopy(BigInt.toByteArray(), 0, large_int_b,
                    large_int_b.length - int_len, int_len);
        }

        return large_int_b;
    }

    public static BigInteger randomBigNat(int maxNumBitLength) {
        Random rnd = new Random();
        BigInteger aRandomBigInt;
        do {
            aRandomBigInt = new BigInteger(maxNumBitLength, rnd);

        } while (aRandomBigInt.compareTo(new BigInteger("1")) < 1);
        return aRandomBigInt;
    }

    /**
     * Permissions are compressed into a short which is later sent to cards
     *
     * @param permissions array
     * @return a short
     */
    public static short compressACL(short[] permissions) {
        short aclShort = 0x0000;
        for (short permission : permissions) {
            aclShort = (short) (aclShort | permission);
        }
        return aclShort;
    }

    private static byte[] ECPointSerialization(ECPoint apoint) {
        // Create a point array that is the size of the two coordinates + prefix
        // used by javacard
        byte[] ECPoint_serial = new byte[1 + 2 * (SecP256r1.KEY_LENGTH / 8)];

        ECFieldElement x = apoint.getAffineXCoord();
        ECFieldElement y = apoint.getAffineYCoord();

        byte[] tempBufferx = new byte[256 / 8];
        if (x.toBigInteger().toByteArray().length == (256 / 8)) {
            tempBufferx = x.toBigInteger().toByteArray();
        } else { // 33
            System.arraycopy(x.toBigInteger().toByteArray(), 1, tempBufferx, 0,
                    (256 / 8));
        }

        // src -- This is the source array.
        // srcPos -- This is the starting position in the source array.
        // dest -- This is the destination array.
        // destPos -- This is the starting position in the destination data.
        // length -- This is the number of array elements to be copied.
        byte[] tempBuffery = new byte[256 / 8];
        if (y.toBigInteger().toByteArray().length == (256 / 8)) {
            tempBuffery = y.toBigInteger().toByteArray();
        } else { // 33
            System.arraycopy(y.toBigInteger().toByteArray(), 1, tempBuffery, 0,
                    (256 / 8));
        }

        byte[] O4 = {(byte) 0x04};
        System.arraycopy(O4, 0, ECPoint_serial, 0, 1);

        // copy x into start of ECPoint_serial (from pos 1, copy x.length bytes)
        System.arraycopy(tempBufferx, 0, ECPoint_serial, 1, tempBufferx.length);

        // copy y into end of ECPoint_serial (from pos x.length+1, copy y.length
        // bytes)
        System.arraycopy(tempBuffery, 0, ECPoint_serial,
                1 + tempBufferx.length, tempBuffery.length);

        // System.out.println((bytesToHex(ECPoint_serial)));
        return ECPoint_serial;
    }

    private static ECPoint randECPoint() throws Exception {
        ECParameterSpec ecSpec_named = ECNamedCurveTable
                .getParameterSpec("secp256r1"); // NIST P-256
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecSpec_named);
        KeyPair apair = kpg.generateKeyPair();
        ECPublicKey apub = (ECPublicKey) apair.getPublic();
        return apub.getQ();
    }

    public static void buildPerfMapping() {
        PERF_STOP_MAPPING.put(PM.PERF_START, "PERF_START");

        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_1, "TRAP_CRYPTOPS_ENCRYPT_1");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_2, "TRAP_CRYPTOPS_ENCRYPT_2");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_3, "TRAP_CRYPTOPS_ENCRYPT_3");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_4, "TRAP_CRYPTOPS_ENCRYPT_4");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_5, "TRAP_CRYPTOPS_ENCRYPT_5");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_6, "TRAP_CRYPTOPS_ENCRYPT_6");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_COMPLETE, "TRAP_CRYPTOPS_ENCRYPT_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_DECRYPTSHARE_1, "TRAP_CRYPTOPS_DECRYPTSHARE_1");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_DECRYPTSHARE_2, "TRAP_CRYPTOPS_DECRYPTSHARE_2");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_DECRYPTSHARE_COMPLETE, "TRAP_CRYPTOPS_DECRYPTSHARE_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_1, "TRAP_CRYPTOPS_SIGN_1");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_2, "TRAP_CRYPTOPS_SIGN_2");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_3, "TRAP_CRYPTOPS_SIGN_3");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_4, "TRAP_CRYPTOPS_SIGN_4");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_5, "TRAP_CRYPTOPS_SIGN_5");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_6, "TRAP_CRYPTOPS_SIGN_6");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_7, "TRAP_CRYPTOPS_SIGN_7");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_8, "TRAP_CRYPTOPS_SIGN_8");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_9, "TRAP_CRYPTOPS_SIGN_9");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_10, "TRAP_CRYPTOPS_SIGN_10");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_COMPLETE, "TRAP_CRYPTOPS_SIGN_COMPLETE");
    }

    public static String getPerfStopName(short stopID) {
        if (PERF_STOP_MAPPING.containsKey(stopID)) {
            return PERF_STOP_MAPPING.get(stopID);
        } else {
            assert (false);
            return "PERF_UNDEFINED";
        }
    }

    public static short getPerfStopFromName(String stopName) {
        for (Short stopID : PERF_STOP_MAPPING.keySet()) {
            if (PERF_STOP_MAPPING.get(stopID).equalsIgnoreCase(stopName)) {
                return stopID;
            }
        }
        assert (false);
        return PM.TRAP_UNDEFINED;
    }

    public static void assertIfSelected(boolean operationResult) {
        assert !_FAIL_ON_ASSERT || (operationResult);
    }

    /* TODO: move to card where channel is known   
     static long PerfAnalyzeCommand(String operationName, CommandAPDU cmd, CardChannel channel, MPCRunConfig cfg) throws CardException, IOException {
     System.out.println(operationName);
     short prevPerfStop = PM.PERF_START;
     long prevTransmitTime = 0;
     long lastFromPrevTime = 0;
     try {
     for (short perfStop : cfg.perfStops) {
     System.arraycopy(Util.shortToByteArray(perfStop), 0, PERF_COMMAND, ISO7816.OFFSET_CDATA, 2); // set required stop condition
     String operationNamePerf = String.format("%s_%s", operationName, getPerfStopName(perfStop));
     transmit(channel, new CommandAPDU(PERF_COMMAND)); // set performance trap
     ResponseAPDU response = transmit(channel, cmd); // execute target operation
     boolean bFailedToReachTrap = false;
     if (perfStop != cfg.perfStopComplete) { // Check expected error to be equal performance trap
     if (response.getSW() != (perfStop & 0xffff)) {
     // we have not reached expected performance trap
     cfg.failedPerfTraps.add(getPerfStopName(perfStop));
     bFailedToReachTrap = true;
     }
     }
     long fromPrevTime = m_lastTransmitTime - prevTransmitTime;
     if (bFailedToReachTrap) {
     cfg.perfResultsSubparts.add(String.format("[%s-%s], \tfailed to reach after %d ms (0x%x)", getPerfStopName(prevPerfStop), getPerfStopName(perfStop), m_lastTransmitTime, response.getSW()));
     } else {
     cfg.perfResultsSubparts.add(String.format("[%s-%s], \t%d ms", getPerfStopName(prevPerfStop), getPerfStopName(perfStop), fromPrevTime));
     cfg.perfResultsSubpartsRaw.put(perfStop, new Pair(prevPerfStop, fromPrevTime));
     lastFromPrevTime = fromPrevTime;
     }

     prevPerfStop = perfStop;
     prevTransmitTime = m_lastTransmitTime;
     }
     } catch (Exception e) {
     // Print what we have measured so far
     for (String res : cfg.perfResultsSubparts) {
     System.out.println(res);
     }
     throw e;
     }
     // Print measured performance info
     for (String res : cfg.perfResultsSubparts) {
     System.out.println(res);
     }

     return lastFromPrevTime;
     }    
     */
    static void SavePerformanceResults(HashMap<Short, Map.Entry<Short, Long>> perfResultsSubpartsRaw, String fileName) throws IOException {
        // Save performance traps into single file
        FileOutputStream perfLog = new FileOutputStream(fileName);
        String output = "perfID, previous perfID, time difference between perfID and previous perfID (ms)\n";
        perfLog.write(output.getBytes());
        for (Short perfID : perfResultsSubpartsRaw.keySet()) {
            output = String.format("%d, %d, %d\n", perfID, perfResultsSubpartsRaw.get(perfID).getKey(), perfResultsSubpartsRaw.get(perfID).getValue());
            perfLog.write(output.getBytes());
        }
        perfLog.close();
    }

    static void InsertPerfInfoIntoFiles(String basePath, String cardName, String experimentID, HashMap<Short, Map.Entry<Short, Long>> perfResultsSubpartsRaw) throws IOException {
        File dir = new File(basePath);
        String[] filesArray = dir.list();
        if ((filesArray != null) && (dir.isDirectory() == true)) {
            // make subdir for results
            String outputDir = String.format("%s\\perf\\%s\\", basePath, experimentID);
            new File(outputDir).mkdirs();

            for (String fileName : filesArray) {
                File dir2 = new File(basePath + fileName);
                if (!dir2.isDirectory()) {
                    InsertPerfInfoIntoFile(String.format("%s\\%s", basePath, fileName), cardName, experimentID, outputDir, perfResultsSubpartsRaw);
                }
            }
        }
    }

    static void InsertPerfInfoIntoFile(String filePath, String cardName, String experimentID, String outputDir, HashMap<Short, Map.Entry<Short, Long>> perfResultsSubpartsRaw) throws IOException {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filePath));
            String basePath = filePath.substring(0, filePath.lastIndexOf("\\"));
            String fileName = filePath.substring(filePath.lastIndexOf("\\"));

            String fileNamePerf = String.format("%s\\%s", outputDir, fileName);
            FileOutputStream fileOut = new FileOutputStream(fileNamePerf);
            String strLine;
            String resLine;
            // For every line of program try to find perfromance trap. If found and perf. is available, then insert comment into code
            while ((strLine = br.readLine()) != null) {

                if (strLine.contains(PERF_TRAP_CALL)) {
                    int trapStart = strLine.indexOf(PERF_TRAP_CALL);
                    int trapEnd = strLine.indexOf(PERF_TRAP_CALL_END);
                    // We have perf. trap, now check if we also corresponding measurement
                    String perfTrapName = strLine.substring(trapStart + PERF_TRAP_CALL.length(), trapEnd);
                    short perfID = getPerfStopFromName(perfTrapName);

                    if (perfResultsSubpartsRaw.containsKey(perfID)) {
                        // We have measurement for this trap, add into comment section
                        resLine = String.format("%s // %d ms (%s,%s) %s", strLine.substring(0, trapEnd + PERF_TRAP_CALL_END.length()), perfResultsSubpartsRaw.get(perfID).getValue(), cardName, experimentID, strLine.subSequence(trapEnd + PERF_TRAP_CALL_END.length(), strLine.length()));
                    } else {
                        resLine = strLine;
                    }
                } else {
                    resLine = strLine;
                }
                resLine += "\n";
                fileOut.write(resLine.getBytes());
            }

            fileOut.close();
        } catch (Exception e) {
            System.out.println(String.format("Failed to transform file %s ", filePath) + e);
        }
    }

    static class HostObj {
        public byte[] host_id;
        public short permissions;
        public BigInteger privateKey;
        public ECPoint publicKey;
        public PrivateKey privateKeyObject;

        HostObj(short[] permissions) throws Exception {
            this.permissions = compressACL(permissions);
            generateKeys();
            host_id = Arrays.copyOfRange(publicKey.getEncoded(false), 0, 4);
        }

        void generateKeys() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
            SecureRandom random = new SecureRandom();

            privateKey = new BigInteger(256, random);
            publicKey = mpcGlobals.G.multiply(privateKey);

            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            org.bouncycastle.jce.spec.ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("SecP256r1");
            ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(privateKey, spec);

            privateKeyObject = keyFactory.generatePrivate(ecPrivateKeySpec);
        }
    }

}
