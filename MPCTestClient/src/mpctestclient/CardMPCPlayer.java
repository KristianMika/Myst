package mpctestclient;

import ds.ov2.bignat.Bignat;
import mpc.Consts;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.testng.internal.collections.Pair;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Implementation of MPCPlayer used with real cards
 *
 * @author Petr Svenda
 */
public class CardMPCPlayer implements MPCPlayer {

    CardChannel channel = null;
    String logFormat = "%-40s:%s%n\n-------------------------------------------------------------------------------\n";
    Long lastTransmitTime;
    boolean bFailOnAssert = true;
    HashMap<Short, QuorumContext> quorumsCtxMap;
    MPCGlobals mpcGlobals;
    SecureRandom randomGen;

    CardMPCPlayer(CardChannel channel, String logFormat, Long lastTransmitTime, boolean bFailOnAssert, MPCGlobals mpcGlobals) {
        this.channel = channel;
        this.logFormat = logFormat;
        this.lastTransmitTime = lastTransmitTime;
        this.bFailOnAssert = bFailOnAssert;
        this.quorumsCtxMap = new HashMap<>();
        this.mpcGlobals = mpcGlobals;
        this.randomGen = new SecureRandom();
    }

    static byte[] preparePacketData(byte operationCode, int numShortParams, Short param1, Short param2, Short param3) {
        int offset = 0;
        byte[] cmd = new byte[1 + 2 + 1 + 2 + numShortParams * 2];
        cmd[offset] = Consts.TLV_TYPE_MPCINPUTPACKET;
        offset++;
        Util.shortToByteArray((short) (cmd.length - 3), cmd, offset);
        offset += 2;
        cmd[offset] = operationCode;
        offset++;
        Util.shortToByteArray((short) (2 * 2), cmd, offset);
        offset += 2;
        if (numShortParams >= 1) {
            offset = Util.shortToByteArray(param1, cmd, offset);
        }
        if (numShortParams >= 2) {
            offset = Util.shortToByteArray(param2, cmd, offset);
        }
        if (numShortParams >= 3) {
            offset = Util.shortToByteArray(param3, cmd, offset);
        }

        return cmd;
    }

    //
    // MPCPlayer methods
    //
    @Override
    public short GetPlayerIndex(short quorumIndex) {
        return quorumsCtxMap.get(quorumIndex).playerIndex;
    }

    @Override
    public byte[] GetPubKeyHash(short quorumIndex) {
        return quorumsCtxMap.get(quorumIndex).pub_key_Hash;
    }

    @Override
    public BigInteger GetE(short quorumIndex) {
        return quorumsCtxMap.get(quorumIndex).card_e_BI;
    }

    @Override
    public ECPoint GetPubKey(short quorumIndex) {
        return quorumsCtxMap.get(quorumIndex).pubKey;
    }

    @Override
    public ECPoint GetAggregatedPubKey(short quorumIndex) {
        return quorumsCtxMap.get(quorumIndex).AggPubKey;
    }

    @Override
    public byte[] Gen_Rin(short quorumIndex, short i, byte[] hostId, PrivateKey hostPrivKey) throws Exception {
        byte[] rin = RetrieveRI(channel, quorumIndex, i, hostId, hostPrivKey);
        System.out.format(logFormat, "Retrieve Ri,n (INS_SIGN_RETRIEVE_RI):", Util.bytesToHex(rin));
        return rin;
    }

    @Override
    public void disconnect() {
        try {
            channel.getCard().disconnect(true); // Disconnect from the card
        } catch (CardException ex) {
            Logger.getLogger(CardMPCPlayer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //
    // CardMPCPlayer public methods
    //
    public void SetBackdoorExample(CardChannel channel, boolean bMakeBackdoored)
            throws Exception {

        CommandAPDU cmd;
        if (bMakeBackdoored) {
            // If to be backdoored, set p1 to 0x55
            cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SET_BACKDOORED_EXAMPLE, 0x55, 0x00, 0x00);
        } else {
            cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SET_BACKDOORED_EXAMPLE, 0x00, 0x00, 0x00);
        }
        ResponseAPDU response = transmit(channel, cmd);
    }

    // TODO: Just a debug function ? remove when protocol is ready : add host verification
    public boolean GetCardInfo() throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_PERSONALIZE_GETCARDINFO, 0, 0);
        ResponseAPDU response = transmit(channel, cmd);

        // Parse response 
        if (response.getSW() == (Consts.SW_SUCCESS & 0xffff)) {
            int offset = 0;
            byte[] data = response.getData();
            System.out.println("---CARD STATE -------");
            assert (data[offset] == Consts.TLV_TYPE_CARDUNIQUEDID);
            offset++;
            short len = Util.getShort(data, offset);
            offset += 2;
            System.out.println(String.format("CardIDLong:\t\t\t %s", Util.toHex(data, offset, len)));
            offset += len;

            assert (data[offset] == Consts.TLV_TYPE_KEYPAIR_STATE);
            offset++;
            assert (Util.getShort(data, offset) == 2);
            offset += 2;
            System.out.println(String.format("KeyPair state:\t\t\t %d", Util.getShort(data, offset)));
            offset += 2;
            assert (data[offset] == Consts.TLV_TYPE_EPHIMERAL_STATE);
            offset++;
            assert (Util.getShort(data, offset) == 2);
            offset += 2;
            System.out.println(String.format("EphiKey state:\t\t\t %d", Util.getShort(data, offset)));
            offset += 2;

            assert (data[offset] == Consts.TLV_TYPE_MEMORY);
            offset++;
            assert (Util.getShort(data, offset) == 6);
            offset += 2;
            System.out.println(String.format("MEMORY_PERSISTENT:\t\t %d bytes", Util.getShort(data, offset)));
            offset += 2;
            System.out.println(String.format("MEMORY_TRANSIENT_RESET:\t\t %d bytes", Util.getShort(data, offset)));
            offset += 2;
            System.out.println(String.format("MEMORY_TRANSIENT_DESELECT:\t %d bytes", Util.getShort(data, offset)));
            offset += 2;
            System.out.println("-----------------");

            assert (data[offset] == Consts.TLV_TYPE_COMPILEFLAGS);
            offset++;
            assert (Util.getShort(data, offset) == 4);
            offset += 2;
            System.out.println(String.format("Consts.MAX_N_PLAYERS:\t\t %d", Util.getShort(data, offset)));
            offset += 2;
            System.out.println(String.format("DKG.PLAYERS_IN_RAM:\t\t %b", data[offset] != 0));
            offset++;
            System.out.println(String.format("DKG.COMPUTE_Y_ONTHEFLY:\t\t %b ", data[offset] != 0));
            offset++;
            System.out.println("-----------------");

            assert (data[offset] == Consts.TLV_TYPE_GITCOMMIT);
            offset++;
            len = Util.getShort(data, offset);
            assert (len == 4);
            offset += 2;
            System.out.println(String.format("Git commit tag:\t\t\t 0x%s", Util.toHex(data, offset, len)));
            offset += len;
            System.out.println("-----------------");

            assert (data[offset] == Consts.TLV_TYPE_EXAMPLEBACKDOOR);
            offset++;
            len = Util.getShort(data, offset);
            assert (len == 1);
            offset += 2;
            if (data[offset] == (byte) 0) {
                System.out.println("Applet is in normal (non-backdoored) state");
            } else {
                System.out.println("WARNING: Applet is in example 'backdoored' state with fixed private key");
            }
            offset += len;
            System.out.println("-----------------");
        }

        return checkSW(response);
    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B host's permissions | <HOST_ID_SIZE>B host's ID | pubKey | signature
     * Incoming packet: response code
     */
    @Override
    public boolean SetHostAuthPubkey(ECPoint pubkey, short hostPermissions, short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception {
        byte[] pubkeyByte = pubkey.getEncoded(false);

        byte[] packetData = preparePacketData(Consts.INS_PERSONALIZE_SET_USER_AUTH_PUBKEY, quorumIndex, hostPermissions);

        CommandAPDU cmd = GenAndSignPacket(Consts.INS_PERSONALIZE_SET_USER_AUTH_PUBKEY, hostPrivKey, (byte) 0x00,
                (byte) 0x00, Util.concat(Util.concat(packetData, hostId), pubkeyByte));
        ResponseAPDU response = transmit(channel, cmd);

        return checkSW(response);
    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B short i | <HOST_ID_SIZE>B host's ID | signature
     * Incoming packet: 65B RI | 2B signature Length | yB signature
     */
    private byte[] RetrieveRI(CardChannel channel, short quorumIndex, short i, byte[] hostId, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_SIGN_RETRIEVE_RI, quorumIndex, i);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_SIGN_RETRIEVE_RI, hostPrivKey, (byte) 0x00, (byte) 0x00, Util.concat(packetData, hostId));
        ResponseAPDU response = transmit(channel, cmd);

        ///We do nothing with the key, as we just use the Aggregated R in the test cases
        checkSW(response);
        byte[] data = response.getData();

        return parseAndVerifySignature(data, 0, 65, quorumIndex);
    }

    private ResponseAPDU transmit(CardChannel channel, CommandAPDU cmd)
            throws CardException {
        log(cmd);

        long elapsed = -System.currentTimeMillis();
        ResponseAPDU response = channel.transmit(cmd);
        elapsed += System.currentTimeMillis();
        lastTransmitTime = elapsed;
        log(response, elapsed);

        return response;
    }

    private void log(CommandAPDU cmd) {
        System.out.printf("--> %s\n", Util.toHex(cmd.getBytes()),
                cmd.getBytes().length);
    }

    private void log(ResponseAPDU response, long time) {
        String swStr = String.format("%02X", response.getSW());
        byte[] data = response.getData();
        if (data.length > 0) {
            System.out.printf("<-- %s %s (%d)\n", Util.toHex(data), swStr,
                    data.length);
        } else {
            System.out.printf("<-- %s\n", swStr);
        }
        if (time > 0) {
            System.out.printf(String.format("Elapsed time %d ms\n", time));
        }
    }

    private void log(ResponseAPDU response) {
        log(response, 0);
    }

    byte[] preparePacketData(byte operationCode, short param1) {
        return preparePacketData(operationCode, 1, param1, null, null);
    }

    byte[] preparePacketData(byte operationCode, short param1, short param2) {
        return preparePacketData(operationCode, 2, param1, param2, null);
    }

    byte[] preparePacketData(byte operationCode, short param1, short param2, short param3) {
        return preparePacketData(operationCode, 3, param1, param2, param3);
    }

    /**
     * Performs EC Diffie Hellman exchange and computes a shared secret.
     *
     * @param quorumIndex quorum Index
     * @param hostId      host's ID
     * @param hostPrivKey host's private key used for signature
     * @return a shared secret as a byte array
     * @throws Exception if fails
     *                   <p>
     *                   Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B - ephem key length | <HOST_ID_SIZE>B host's ID | ephem key |  signature
     *                   Incoming packet:
     */
    byte[] performDHExchange(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception {

        // Generate server's key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        java.security.spec.ECPoint ephemPubKeyPoint = ((ECPublicKey) kp.getPublic()).getW();
        ECPoint newPoint = mpcGlobals.curve.createPoint(ephemPubKeyPoint.getAffineX(), ephemPubKeyPoint.getAffineY());
        byte[] ephemPubKeyEnc = newPoint.getEncoded(false);

        // send ephemPubKeyEnc to the card
        byte[] packetData = preparePacketData(Consts.INS_ECDH_EXCHANGE, quorumIndex, (short) ephemPubKeyEnc.length);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_ECDH_EXCHANGE, hostPrivKey, (byte) 0x00, (byte) 0x00,
                Util.concat(Util.concat(packetData, hostId), ephemPubKeyEnc));

        ResponseAPDU response = transmit(channel, cmd);
        checkSW(response);
        byte[] responseData = response.getData();

        short keyLength = Util.getShort(responseData, 0);
        short sigLen = Util.getShort(responseData, 2 + keyLength);
        // verify signature
        byte[] signature = Arrays.copyOfRange(responseData, 2 + keyLength + 2, 2 + keyLength + 2 + sigLen);
        byte[] data = Arrays.copyOfRange(responseData, 0, 2 + keyLength);
        if (!verifyECDSASignature(data, signature, quorumsCtxMap.get(quorumIndex).pubkeyObject)) {
            throw new SecurityException("Signature verification failed");
        }

        // reconstruct the card's public key
        byte[] receivedPubKey = Arrays.copyOfRange(data, 2, 2 + keyLength);
        ECPoint receivedECPoint = Util.ECPointDeSerialization(mpcGlobals.curve, receivedPubKey, 0);  // Store Pub

        BigInteger x = receivedECPoint.normalize().getXCoord().toBigInteger();
        BigInteger y = receivedECPoint.normalize().getYCoord().toBigInteger();

        ECNamedCurveSpec params = new ECNamedCurveSpec("SecP256r1", mpcGlobals.curve, mpcGlobals.G, mpcGlobals.n);
        java.security.spec.ECPoint w = new java.security.spec.ECPoint(x, y);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey ecPubKey = keyFactory.generatePublic(new java.security.spec.ECPublicKeySpec(w, params));

        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(kp.getPrivate());
        agreement.doPhase(ecPubKey, true);
        byte[] sharedSecret = agreement.generateSecret();

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(sharedSecret);
        md.update(ephemPubKeyEnc);
        md.update(receivedPubKey);

        return md.digest();

    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B - numPlayers | 2B - thisPlayerIndex|
     * <HOST_ID_SIZE>B host's ID | signature
     * Incoming packet: response code
     */
    @Override
    public boolean Setup(short quorumIndex, short numPlayers, short thisPlayerIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception {
        quorumsCtxMap.put(quorumIndex, new QuorumContext(quorumIndex, thisPlayerIndex, numPlayers));
        byte[] packetData = preparePacketData(Consts.INS_QUORUM_SETUP_NEW, quorumIndex, numPlayers, thisPlayerIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_QUORUM_SETUP_NEW, hostPrivKey, (byte) 0x00, (byte) 0x00, Util.concat(packetData, hostId));
        ResponseAPDU response = transmit(channel, cmd);

        return checkSW(response);
    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | signature
     * Incoming packet: response code
     */
    @Override
    public boolean Reset(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_QUORUM_RESET, quorumIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_QUORUM_RESET, hostPrivKey, (byte) 0x00, (byte) 0x00, Util.concat(packetData, hostId));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | signature
     * Incoming packet: response code
     */
    @Override
    public boolean Remove(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_QUORUM_REMOVE, quorumIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_QUORUM_REMOVE, hostPrivKey, (byte) 0x00, (byte) 0x00, Util.concat(packetData, hostId));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | nonce | signature
     * Incoming packet: 2B 0x9000 |card's nonce | signature(nonce, 0x900, card's nonce)
     */
    @Override
    public boolean GenKeyPair(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_INIT, quorumIndex);
        byte[] nonce = new byte[Consts.APDU_SIG_NONCE_SIZE];
        randomGen.nextBytes(nonce);

        CommandAPDU cmd = GenAndSignPacket(Consts.INS_KEYGEN_INIT, hostPrivKey, (byte) 0x00, (byte) 0x00,
                Util.concat(Util.concat(packetData, hostId), nonce));
        ResponseAPDU response = transmit(channel, cmd);
        checkSW(response);
        // store (nonce, returned bytes) as a plaintext
        saveSignature(Util.concat(nonce, response.getBytes()), 0, Consts.APDU_SIG_NONCE_SIZE * 2 + 2, quorumIndex);

        return checkSW(response);
    }


    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | signature
     * Incoming packet: 2B - data length | data (commitment) | signature
     */
    @Override
    public boolean RetrievePubKeyHash(short quorumIndex, byte[] host_id, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_RETRIEVE_COMMITMENT, quorumIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_KEYGEN_RETRIEVE_COMMITMENT, hostPrivKey, (byte) 0x0, (byte) 0x0, Util.concat(packetData, host_id));

        ResponseAPDU response = transmit(channel, cmd);
        checkSW(response);
        byte[] responseData = response.getData();
        short dataLen = Util.getShort(responseData, 0);
        short sigLen = Util.getShort(responseData, 2 + dataLen);

        byte[] pubKeyHash = Arrays.copyOfRange(responseData, 2, 2 + dataLen);
        byte[] signature = Arrays.copyOfRange(responseData, 2 + dataLen + 2, 2 + dataLen + 2 + sigLen);
        quorumsCtxMap.get(quorumIndex).pub_key_Hash = pubKeyHash;

        // signature is verified after the public key is received
        quorumsCtxMap.get(quorumIndex).signaturesToVerify.add(new Pair<>(pubKeyHash, signature));

        return checkSW(response);
    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B - player's index| 2B hash length |
     * <HOST_ID_SIZE>B host's ID | nonce | hash | signature
     * Incoming packet: 2B 0x9000 | card's nonce | signature(nonce, 0x9000, card's nonce)
     */
    @Override
    public boolean StorePubKeyHash(short quorumIndex, short id,
                                   byte[] hash_arr, byte[] hostId, PrivateKey hostPrivKey) throws Exception {

        byte[] nonce = new byte[Consts.APDU_SIG_NONCE_SIZE];
        randomGen.nextBytes(nonce);

        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_STORE_COMMITMENT, quorumIndex, id, (short) hash_arr.length);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_KEYGEN_STORE_COMMITMENT, hostPrivKey, (byte) 0x0, (byte) 0x0,
                Util.concat(Util.concat(packetData, hostId), Util.concat(nonce, hash_arr)));
        ResponseAPDU response = transmit(channel, cmd);

        checkSW(response);
        // store (nonce, returned bytes) as a plaintext
        saveSignature(Util.concat(nonce, response.getBytes()), 0, Consts.APDU_SIG_NONCE_SIZE * 2 + 2, quorumIndex);
        return checkSW(response);
    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B - player's index| 2B key length |
     * <HOST_ID_SIZE>B host's ID | nonce | key | signature
     * Incoming packet: 2B 0x9000 | card's nonce | signature(nonce, 0x9000, card's nonce)
     */
    @Override
    public boolean StorePubKey(short quorumIndex, short id,
                               byte[] pub_arr, byte[] hostId, PrivateKey hostPrivKey) throws Exception {

        byte[] nonce = new byte[Consts.APDU_SIG_NONCE_SIZE];
        randomGen.nextBytes(nonce);

        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_STORE_PUBKEY, quorumIndex, id, (short) pub_arr.length);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_KEYGEN_STORE_PUBKEY, hostPrivKey, (byte) 0x0, (byte) 0x0,
                Util.concat(Util.concat(packetData, hostId), Util.concat(nonce, pub_arr)));
        ResponseAPDU response = transmit(channel, cmd);

        checkSW(response);
        // verify (nonce, returned bytes) as a plaintext
        parseAndVerifySignature(Util.concat(nonce, response.getBytes()), 0, Consts.APDU_SIG_NONCE_SIZE * 2 + 2, quorumIndex);
        return checkSW(response);
    }


    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | signature
     * Incoming packet: 65B data (PubKey) | signature
     */
    @Override
    public byte[] RetrievePubKey(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey, MPCGlobals mpcGlobals) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_RETRIEVE_PUBKEY, quorumIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_KEYGEN_RETRIEVE_PUBKEY, hostPrivKey, (byte) 0x0, (byte) 0x0, Util.concat(packetData, hostId));
        ResponseAPDU response = transmit(channel, cmd);
        checkSW(response);

        byte[] responseData = response.getData();
        byte[] data = Arrays.copyOfRange(responseData, 0, 65);
        short sigLen = Util.getShort(responseData, 65);
        byte[] signature = Arrays.copyOfRange(responseData, 65 + 2, 65 + 2 + sigLen);

        quorumsCtxMap.get(quorumIndex).pubKey = Util.ECPointDeSerialization(mpcGlobals.curve, data, 0);  // Store Pub

        // set PublicKey object
        BigInteger x = quorumsCtxMap.get(quorumIndex).pubKey.normalize().getXCoord().toBigInteger();
        BigInteger y = quorumsCtxMap.get(quorumIndex).pubKey.normalize().getYCoord().toBigInteger();
        ECNamedCurveSpec params = new ECNamedCurveSpec("SecP256r1", mpcGlobals.curve, mpcGlobals.G, mpcGlobals.n);
        java.security.spec.ECPoint w = new java.security.spec.ECPoint(x, y);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        quorumsCtxMap.get(quorumIndex).pubkeyObject = keyFactory.generatePublic(new java.security.spec.ECPublicKeySpec(w, params));
        QuorumContext thisQContext = quorumsCtxMap.get(quorumIndex);

        // verifies INS_KEYGEN_RETRIEVE_PUBKEY signature
        if (!verifyECDSASignature(data, signature, quorumsCtxMap.get(quorumIndex).pubkeyObject)) {
            quorumsCtxMap.get(quorumIndex).pubkeyObject = null;
            quorumsCtxMap.get(quorumIndex).pubKey = null;
            throw new SecurityException("Signature verification failed");
        }

        // verify all signatures that have been stored since the beginning of the protocol run
        for (Pair<byte[], byte[]> pair : quorumsCtxMap.get(quorumIndex).signaturesToVerify) {
            if (!verifyECDSASignature(pair.first(), pair.second(), quorumsCtxMap.get(quorumIndex).pubkeyObject)) {
                throw new InvalidCardSignatureException();
            }
        }
        return data;
    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | signature
     * Incoming packet: 2B - data length | data (Yagg) | signature
     */
    @Override
    public boolean RetrieveAggPubKey(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey)
            throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_RETRIEVE_AGG_PUBKEY, quorumIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_KEYGEN_RETRIEVE_AGG_PUBKEY, hostPrivKey, (byte) 0x0, (byte) 0x0, Util.concat(packetData, hostId));
        ResponseAPDU response = transmit(channel, cmd);
        byte[] responseData = response.getData();
        checkSW(response);

        short yagg_len = Util.getShort(responseData, 0);
        byte[] data = parseAndVerifySignature(responseData, 2, 2 + yagg_len, quorumIndex);

        quorumsCtxMap.get(quorumIndex).AggPubKey = Util.ECPointDeSerialization(mpcGlobals.curve, data, 0); // Store aggregated pub
        return checkSW(response);
    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B plaintext length | <HOST_ID_SIZE>B host's ID | plaintext | signature
     * Incoming packet: 2B - cipher length | xB cipher | 2B sigLen | yB signature
     */
    @Override
    public byte[] Encrypt(short quorumIndex, byte[] plaintext, byte[] hostId, PrivateKey hostPrivKey)
            throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_ENCRYPT, quorumIndex, (short) plaintext.length);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_ENCRYPT, hostPrivKey, (byte) 0x0, (byte) 0x0,
                Util.concat(Util.concat(packetData, hostId), plaintext));
        ResponseAPDU response = transmit(channel, cmd);
        checkSW(response);
        byte[] data =  response.getData();
        int sigOff = 2 + Util.getShort(data, 0);
        return parseAndVerifySignature(data, 2, sigOff, quorumIndex);
    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B cipher length | <HOST_ID_SIZE>B host's ID | cipher | signature
     * Incoming packet:
     */
    @Override
    public byte[] Decrypt(short quorumIndex, byte[] ciphertext, byte[] hostId, PrivateKey hostPrivKey) throws Exception {
        byte[] sharedSecret = performDHExchange(quorumIndex, hostId, hostPrivKey);

        byte[] packetData = preparePacketData(Consts.INS_DECRYPT, quorumIndex, (short) ciphertext.length);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_DECRYPT, hostPrivKey, (byte) 0x0, (byte) 0x00,
                Util.concat(Util.concat(packetData, hostId), ciphertext));
        ResponseAPDU response = transmit(channel, cmd);
        checkSW(response);

        byte[] responseData = response.getData();

        // parse received packet to data and signature
        short dataLength = Util.getShort(responseData, 0);
        byte[] data = Arrays.copyOfRange(responseData, 0, 2 + dataLength + Consts.IV_LEN);
        short sigLen = Util.getShort(responseData, 2 + dataLength + Consts.IV_LEN);
        int sigOff = 2 + dataLength + Consts.IV_LEN + 2;
        byte[] signature = Arrays.copyOfRange(responseData, sigOff, sigOff + sigLen);
        if (!verifyECDSASignature(data, signature, quorumsCtxMap.get(quorumIndex).pubkeyObject)) {
            throw new GeneralSecurityException("Bogus packet signature.");
        }

        return decryptAes(data, sharedSecret);

    }

    /**
     * Decrypts aes cipher
     *
     * @param responseData input array
     * @param sharedSecret byte array with a shared secret
     * @return decrypted array
     * @throws Exception if fails
     */
    byte[] decryptAes(byte[] responseData, byte[] sharedSecret) throws Exception {
        short cipherLength = Util.getShort(responseData, 0);
        byte[] receivedCipher = Arrays.copyOfRange(responseData, 2, cipherLength + 2);

        byte[] aesIv = Arrays.copyOfRange(responseData, 2 + cipherLength, 2 + cipherLength + 16);

        IvParameterSpec ivSpec = new IvParameterSpec(aesIv);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

        byte[] decrypted = cipher.doFinal(receivedCipher);

        return removeISO9797_m2Padding(decrypted);
    }

    byte[] removeISO9797_m2Padding(byte[] plain) {
        int len = plain.length;
        for (int i = 0; i < plain.length; i++) {
            if (plain[i] == ((byte) 0x80) && (i + 1 == plain.length || plain[i + 1] == ((byte) 0x00))) {
                len = i;
                break;
            }
        }
        return Arrays.copyOfRange(plain, 0, len);
    }

    @Override
    public BigInteger Sign(short quorumIndex, int round, byte[] Rn, byte[] plaintext, byte[] hostId, PrivateKey hostPrivKey) throws Exception {

        //String operationName = String.format("Signature(%s) (INS_SIGN)", msgToSign.toString());
        byte[] signature = Sign_plain(quorumIndex, round, plaintext, Rn, hostId, hostPrivKey);

        //Parse s from Card
        Bignat card_s_Bn = new Bignat((short) 32, false);
        card_s_Bn.from_byte_array((short) 32, (short) 0, signature, (short) 0);
        BigInteger card_s_bi = new BigInteger(1, card_s_Bn.as_byte_array());

        //Parse e from Card
        Bignat card_e_Bn = new Bignat((short) 32, false);
        card_e_Bn.from_byte_array((short) 32, (short) 0, signature, (short) 32);
        quorumsCtxMap.get(quorumIndex).card_e_BI = new BigInteger(1, card_e_Bn.as_byte_array());

        //System.out.println("REALCARD : s:        " + bytesToHex(card_s_Bn.as_byte_array()));
        //System.out.println("REALCARD : e:        " + bytesToHex(card_e_Bn.as_byte_array()) + "\n");
        return card_s_bi;
    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B - round | 2B plaintext + Rn length | <HOST_ID_SIZE>B host's ID | plaintext | Rn | signature
     * Incoming packet: signature of the data
     */
    // TODO: verify signature
    public byte[] Sign_plain(short quorumIndex, int round, byte[] plaintext, byte[] Rn, byte[] hostId, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_SIGN, quorumIndex, (short) round, (short) ((short) plaintext.length + (short) Rn.length));
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_SIGN, hostPrivKey, (byte) round, (byte) 0x00, Util.concat(Util.concat(packetData, hostId), Util.concat(plaintext, Rn)));
        ResponseAPDU response = transmit(channel, cmd);
        checkSW(response);
        return response.getData();
    }

    /**
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B - num of bytes | <HOST_ID_SIZE>B host's ID | signature
     * Incoming packet: 2B cipher len | xB E_sym(2B number of generated bytes | xB generated bytes) | signature
     */
    @Override
    public byte[] GenerateRandom(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey, short numOfBytes) throws Exception {
        byte[] shared_secret = performDHExchange(quorumIndex, hostId, hostPrivKey);

        byte[] packetData = preparePacketData(Consts.INS_GENERATE_RANDOM, quorumIndex, numOfBytes);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_GENERATE_RANDOM, hostPrivKey, (byte) 0x0, (byte) 0x00, Util.concat(packetData, hostId));
        ResponseAPDU response = transmit(channel, cmd);
        checkSW(response);

        byte[] responseData = response.getData();
        short cipherLen = Util.getShort(responseData, 0);

        // TODO: USE CONSTANT VARIABLES FOR OFFSETS (WILL IMPLEMENT LATER)

        byte[] data = parseAndVerifySignature(responseData, 0, 2 + cipherLen + 16, quorumIndex);

        byte[] decryptedResp = decryptAes(data, shared_secret);

        if (!(Util.getShort(decryptedResp, 0) == numOfBytes)) {
            throw new GeneralSecurityException("First 2 bytes are not equal to the requested byte array size");
        }

        return Arrays.copyOfRange(decryptedResp, 2, decryptedResp.length);
    }

    private boolean checkSW(ResponseAPDU response) throws MPCException {
        if (response.getSW() != (Consts.SW_SUCCESS & 0xffff)) {
            System.err.printf("Received error status: %02X.\n",
                    response.getSW());
            if (bFailOnAssert) {
                handleReturnCode((short) response.getSW());
            }
            return false;
        }
        return true;
    }

    /**
     * Method for building and signing packets.
     *
     * @param function    (byte) protocol function
     * @param hostPrivKey (PrivateKey) host's private key object
     * @param p1          (byte) the first parameter
     * @param p2          (byte) the second parameter
     * @param data        (byte[]) packet data
     * @return CommandAPDU packet with signature
     * @throws Exception when signing fails
     */
    private CommandAPDU GenAndSignPacket(byte function, PrivateKey hostPrivKey, byte p1, byte p2, byte[] data) throws Exception {
        // Signature can be currently generated only if a packet is smaller than 256 bytes. For longer packets split signature and data into separate APDUs.
        if ((5 + data.length + 72) > 256) { // 72 is upper bound for signature length
            throw new IllegalArgumentException("Packet data length is too long.");
        }
        // Recreate the packet
        byte[] packetCopy = new byte[5 + data.length];
        packetCopy[0] = Consts.CLA_MPC;
        packetCopy[1] = function;
        packetCopy[2] = p1;
        packetCopy[3] = p2;
        packetCopy[4] = (byte) (data.length); // packet has to be shorter then 256 bytes
        System.arraycopy(data, 0, packetCopy, 5, data.length);

        // Sign the packet copy
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        ecdsaSign.initSign(hostPrivKey);
        ecdsaSign.update(packetCopy);
        byte[] signature = ecdsaSign.sign();

        byte[] packetDataWSignature = Util.concat(data, Util.concat(Util.shortToByteArray(signature.length), signature));
        return new CommandAPDU(Consts.CLA_MPC, function, p1, p2, packetDataWSignature);
    }

    void saveSignature(byte[] apdu, int plainOff, int plainLen, short quorumIndex) {
        byte[] plaintext = Arrays.copyOfRange(apdu, plainOff, plainOff + plainLen);
        int sigLenOff = plainOff + plainLen;
        int sigLen = Util.getShort(apdu, sigLenOff);
        byte[] signature = Arrays.copyOfRange(apdu, sigLenOff + 2, sigLenOff + 2 + sigLen);
        quorumsCtxMap.get(quorumIndex).signaturesToVerify.add(new Pair<>(plaintext, signature));
    }

    /**
     * Method for ECDSA signature verification
     *
     * @param data      plaintext
     * @param signature signature
     * @param pubkey    public key as PublicKey object
     * @return verification result
     * @throws GeneralSecurityException in case signature is in incorrect format
     */
    private boolean verifyECDSASignature(byte[] data, byte[] signature, PublicKey pubkey) throws GeneralSecurityException {
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(pubkey);
        ecdsaVerify.update(data);
        return ecdsaVerify.verify(signature);
    }

    /**
     * Parses the packet and calls verifyECDSASignature()
     * Data = xB Data | 2B sigLen | signature
     *
     * @param data    plaintext
     * @param dataOff plaintext offset
     * @param sigOff  signature offset
     * @param quorumI quorum index
     * @return byte array
     * @throws InvalidCardSignatureException
     */
    private byte[] parseAndVerifySignature(byte[] data, int dataOff, int sigOff, short quorumI)
            throws InvalidCardSignatureException, GeneralSecurityException {
        short sigLen = Util.getShort(data, sigOff);
        byte[] signature = Arrays.copyOfRange(data, sigOff + 2, sigOff + 2 + sigLen);
        data = Arrays.copyOfRange(data, dataOff, sigOff);
        PublicKey pubkey = quorumsCtxMap.get(quorumI).pubkeyObject;
        if (!verifyECDSASignature(data, signature, pubkey)) {
            throw new InvalidCardSignatureException();
        }
        return data;
    }

    private boolean TestNativeECAdd(CardChannel channel, ECPoint point1, ECPoint point2) throws Exception {
        // addPoint
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_TESTECC, (byte) 1, point1.getEncoded(false).length, Util.concat(point1.getEncoded(false), point2.getEncoded(false)));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    private boolean TestNativeECMult(CardChannel channel, ECPoint point1, BigInteger scalar) throws Exception {
        // multiply by scalar
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_TESTECC, (byte) 2, point1.getEncoded(false).length, Util.concat(point1.getEncoded(false), scalar.toByteArray()));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    /**
     * Handles the return code from the card and throws a corresponding exception.
     *
     * @param retCode Code returned from the card.
     * @throws MPCException
     */
    void handleReturnCode(short retCode) throws MPCException {
        switch (retCode) {

            case Consts.SW_SUCCESS:
                return;

            case Consts.SW_DUPLICATE_HOST_ID:
                throw new DuplicateHostIdException();

            case Consts.SW_HOSTNOTALLOWED:
                throw new HostNotAllowedException();

            case Consts.SW_INVALID_PACKET_SIGNATURE:
                throw new InvalidHostSignatureException();

            case Consts.SW_INVALID_HOST_ID:
                throw new InvalidHostIdException();

            case Consts.SW_FUNCTINNOTALLOWED:
                throw new FunctionNotAllowedException();

            default:
                throw new MPCException(String.format("0x%02X",retCode));
        }
    }

    static class QuorumContext {

        public byte[] pub_key_Hash;
        short playerIndex;
        short quorumIndex = 0;
        short numPlayers = 0;
        BigInteger card_e_BI;
        ECPoint pubKey;
        PublicKey pubkeyObject;
        ECPoint AggPubKey;
        Bignat requestCounter;
        List<Pair<byte[], byte[]>> signaturesToVerify;


        QuorumContext(short quorumIndex, short playerIndex, short numPlayers) {
            this.quorumIndex = quorumIndex;
            this.playerIndex = playerIndex;
            this.numPlayers = numPlayers;
            requestCounter = new Bignat((short) 2, false);
            requestCounter.zero();
            signaturesToVerify = new ArrayList<>();
        }
    }

    /* Debug only, not supported on real card
     private boolean RetrievePrivKey_DebugOnly(CardChannel channel)
     throws Exception {
     CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC,
     Consts.BUGBUG_INS_KEYGEN_RETRIEVE_PRIVKEY, 0x0, 0x0);
     ResponseAPDU response = transmit(channel, cmd);

     // Store Secret
     Bignat tmp_BN = new Bignat(Consts.SHARE_BASIC_SIZE, false);
     tmp_BN.from_byte_array(Consts.SHARE_BASIC_SIZE, (short) 0, (response.getData()),
     (short) 0);
     mpcGlobals.secret = Convenience.bi_from_bn(tmp_BN);

     return checkSW(response);
     }
     */
    /*    
     private byte[] Encrypt(CardChannel channel, short quorumIndex, byte[] plaintext, MPCRunConfig runCfg, boolean bProfilePerf)
     throws Exception {
     byte[] packetData = preparePacketData(Consts.INS_ENCRYPT, quorumIndex, (short) plaintext.length);
     if (!bProfilePerf) {
     CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_ENCRYPT, 0x0, 0x0, Util.concat(packetData, plaintext));
     ResponseAPDU response = transmit(channel, cmd);
     return response.getData();
     } else {
     transmit(channel, new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 

     short[] PERFSTOPS_Encrypt = {PM.TRAP_CRYPTOPS_ENCRYPT_1, PM.TRAP_CRYPTOPS_ENCRYPT_2, PM.TRAP_CRYPTOPS_ENCRYPT_3, PM.TRAP_CRYPTOPS_ENCRYPT_4, PM.TRAP_CRYPTOPS_ENCRYPT_5, PM.TRAP_CRYPTOPS_ENCRYPT_6, PM.TRAP_CRYPTOPS_ENCRYPT_COMPLETE};
     runCfg.perfStops = PERFSTOPS_Encrypt;
     runCfg.perfStopComplete = PM.TRAP_CRYPTOPS_ENCRYPT_COMPLETE;
     long avgOpTime = 0;
     String opName = "Encrypt: ";
     for (int repeat = 0; repeat < runCfg.numSingleOpRepeats; repeat++) {
     CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_ENCRYPT, 0x0, 0x0, Util.concat(packetData, plaintext));
     avgOpTime += PerfAnalyzeCommand(opName, cmd, channel, runCfg);
     }
     System.out.println(String.format("%s: average time: %d", opName, avgOpTime / runCfg.numSingleOpRepeats));
     transmit(channel, new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 

     return Encrypt(channel, quorumIndex, plaintext, runCfg, false);
     }
     }    
     */
    /*    

     private byte[] Decrypt(CardChannel channel, short quorumIndex, byte[] ciphertext, MPCRunConfig runCfg, boolean bProfilePerf)
     throws Exception {
     byte[] packetData = preparePacketData(Consts.INS_DECRYPT, quorumIndex, (short) ciphertext.length);
     if (!bProfilePerf) {
     CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_DECRYPT, 0x0, 0x0, Util.concat(packetData, ciphertext));
     ResponseAPDU response = transmit(channel, cmd);

     return response.getData();
     } else {
     transmit(channel, new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 

     short[] PERFSTOPS_Decrypt = {PM.TRAP_CRYPTOPS_DECRYPTSHARE_1, PM.TRAP_CRYPTOPS_DECRYPTSHARE_2, PM.TRAP_CRYPTOPS_DECRYPTSHARE_COMPLETE};
     runCfg.perfStops = PERFSTOPS_Decrypt;
     runCfg.perfStopComplete = PM.TRAP_CRYPTOPS_DECRYPTSHARE_COMPLETE;
     long avgOpTime = 0;
     String opName = "Decrypt: ";
     for (int repeat = 0; repeat < runCfg.numSingleOpRepeats; repeat++) {
     CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_DECRYPT, 0x0, 0x0, Util.concat(packetData, ciphertext));
     avgOpTime += PerfAnalyzeCommand(opName, cmd, channel, runCfg);
     }
     System.out.println(String.format("%s: average time: %d", opName, avgOpTime / runCfg.numSingleOpRepeats));
     transmit(channel, new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 

     return Decrypt(channel, quorumIndex, ciphertext, runCfg, false);
     }
     }
     */
    /*
     public byte[] Sign_profilePerf(short quorumIndex, int round, byte[] plaintext, byte[] Rn, MPCRunConfig runCfg, boolean bProfilePerf) throws Exception {
     // Repeated measurements if required
     long elapsed = -System.currentTimeMillis();
     int repeats = 100000;
     for (int i = 1; i < repeats; i++) {
     plaintext[5] = (byte) (i % 256);
     CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN, round, 0x0, concat(plaintext, Rn));
     ResponseAPDU response = transmit(channel, cmd);
     }
     elapsed += System.currentTimeMillis();
     System.out.format("Elapsed: %d ms, time per Sign = %f ms\n", elapsed, elapsed / (float) repeats);

     byte[] packetData = preparePacketData(Consts.INS_SIGN, quorumIndex, (short) round, (short) ((short) plaintext.length + (short) Rn.length));
     if (!bProfilePerf) {
     CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN, round, 0x0, Util.concat(packetData, Util.concat(plaintext, Rn)));
     ResponseAPDU response = transmit(channel, cmd);

     return response.getData();
     } else {
     // Repeated measurements if required
     transmit(channel, new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 

     short[] PERFSTOPS_Decrypt = {PM.TRAP_CRYPTOPS_SIGN_1, PM.TRAP_CRYPTOPS_SIGN_2, PM.TRAP_CRYPTOPS_SIGN_3, PM.TRAP_CRYPTOPS_SIGN_4, PM.TRAP_CRYPTOPS_SIGN_5, PM.TRAP_CRYPTOPS_SIGN_6, PM.TRAP_CRYPTOPS_SIGN_7, PM.TRAP_CRYPTOPS_SIGN_8, PM.TRAP_CRYPTOPS_SIGN_9, PM.TRAP_CRYPTOPS_SIGN_10, PM.TRAP_CRYPTOPS_SIGN_COMPLETE};
     runCfg.perfStops = PERFSTOPS_Decrypt;
     runCfg.perfStopComplete = PM.TRAP_CRYPTOPS_SIGN_COMPLETE;
     long avgOpTime = 0;
     String opName = "Sign: ";
     for (int repeat = 0; repeat < runCfg.numSingleOpRepeats; repeat++) {
     CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN, round, 0x0, Util.concat(packetData, Util.concat(plaintext, Rn)));
     avgOpTime += PerfAnalyzeCommand(opName, cmd, channel, runCfg);
     }
     System.out.println(String.format("%s: average time: %d", opName, avgOpTime / runCfg.numSingleOpRepeats));
     transmit(channel, new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 

     return Sign(channel, quorumIndex, round, plaintext, Rn, runCfg, false);
     }
     }
     /**/
    /*
     private boolean PointAdd(CardChannel channel) throws Exception {
     byte[] PointA = mpcGlobals.G.multiply(BigInteger.valueOf(10)).getEncoded(false);
     byte[] PointB = mpcGlobals.G.multiply(BigInteger.valueOf(20)).getEncoded(false);

     CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_ADDPOINTS, 0x00, 0x00, Util.concat(PointA, PointB));
     ResponseAPDU response = transmit(channel, cmd);
     return checkSW(response);
     }
     */
}
