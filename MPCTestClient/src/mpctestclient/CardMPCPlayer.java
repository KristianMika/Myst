package mpctestclient;

import ds.ov2.bignat.Bignat;
import mpc.Consts;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;

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
import java.util.Arrays;
import java.util.HashMap;
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

    CardMPCPlayer(CardChannel channel, String logFormat, Long lastTransmitTime, boolean bFailOnAssert, MPCGlobals mpcGlobals) {
        this.channel = channel;
        this.logFormat = logFormat;
        this.lastTransmitTime = lastTransmitTime;
        this.bFailOnAssert = bFailOnAssert;
        this.quorumsCtxMap = new HashMap<>();
        this.mpcGlobals = mpcGlobals;
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
    public byte[] Gen_Rin(short quorumIndex, short i, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        byte[] rin = RetrieveRI(channel, quorumIndex, i, hostIndex, hostPrivKey);
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

    public boolean GetCardInfo(byte hostIndex) throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_PERSONALIZE_GETCARDINFO, 0, hostIndex);
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

    @Override
    public boolean SetHostAuthPubkey(ECPoint pubkey, short hostPermissions, short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        byte[] pubkeyByte = pubkey.getEncoded(false);
        byte[] packetData = preparePacketData(Consts.INS_PERSONALIZE_SET_USER_AUTH_PUBKEY, quorumIndex, hostPermissions);
        // Signature is not currently verified!!!
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_PERSONALIZE_SET_USER_AUTH_PUBKEY, hostPrivKey, (byte) 0x00, hostIndex, Util.concat(packetData, pubkeyByte));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    private byte[] RetrieveRI(CardChannel channel, short quorumIndex, short i, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_SIGN_RETRIEVE_RI, quorumIndex, i);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_SIGN_RETRIEVE_RI, hostPrivKey, (byte) 0x00, hostIndex, packetData);
        ResponseAPDU response = transmit(channel, cmd);

        ///We do nothing with the key, as we just use the Aggregated R in the test cases
        // return checkSW(response);
        return response.getData();
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
     * TODO: SIGN THE OUTGOING PACKET
     *
     * @param quorumIndex quorum Index
     * @param hostIndex   host's index
     * @param hostPrivKey host's private key used for signature (not implemented yet)
     * @return a shared secret as a byte array
     * @throws Exception if fails
     */
    byte[] performDHExchange(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception {

        // Generate server's key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        java.security.spec.ECPoint ephemPubKeyPoint = ((ECPublicKey) kp.getPublic()).getW();
        ECPoint newPoint = mpcGlobals.curve.createPoint(ephemPubKeyPoint.getAffineX(), ephemPubKeyPoint.getAffineY());
        byte[] ephemPubKeyEnc = newPoint.getEncoded(false);

        // send ephemPubKeyEnc to the card
        byte[] packetData = preparePacketData(Consts.INS_ECDH_EXCHANGE, quorumIndex, (short) ephemPubKeyEnc.length);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_ECDH_EXCHANGE, hostPrivKey, (byte) 0x00, hostIndex, Util.concat(packetData, ephemPubKeyEnc));

        ResponseAPDU response = transmit(channel, cmd);
        byte[] responseData = response.getData();

        // reconstruct the card's public key
        short keyLength = Util.getShort(responseData, 0);
        byte[] receivedPubKey = Arrays.copyOfRange(responseData, 2, 2 + keyLength);
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

    @Override
    public boolean Setup(short quorumIndex, short numPlayers, short thisPlayerIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        quorumsCtxMap.put(quorumIndex, new QuorumContext(quorumIndex, thisPlayerIndex, numPlayers));
        byte[] packetData = preparePacketData(Consts.INS_QUORUM_SETUP_NEW, quorumIndex, numPlayers, thisPlayerIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_QUORUM_SETUP_NEW, hostPrivKey, (byte) 0x00, hostIndex, packetData);
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    @Override
    public boolean Reset(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_QUORUM_RESET, quorumIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_QUORUM_RESET, hostPrivKey, (byte) 0x00, hostIndex, packetData);
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    @Override
    public boolean Remove(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_QUORUM_REMOVE, quorumIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_QUORUM_REMOVE, hostPrivKey, (byte) 0x00, hostIndex, packetData);
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    @Override
    public boolean GenKeyPair(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_INIT, quorumIndex, hostIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_KEYGEN_INIT, hostPrivKey, (byte) 0x00, hostIndex, packetData);
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    @Override
    public boolean RetrievePubKeyHash(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_RETRIEVE_COMMITMENT, quorumIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_KEYGEN_RETRIEVE_COMMITMENT, hostPrivKey, (byte) 0x0, hostIndex, packetData);
        ResponseAPDU response = transmit(channel, cmd);
        byte[] responseData = response.getData();
        short dataLength = Util.getShort(responseData, 0);
        short sigLength = Util.getShort(responseData, Consts.PACKET_SHORT_PARAM_LENGTH);
        byte[] pubKeyHash = Arrays.copyOfRange(responseData, 2 * Consts.PACKET_SHORT_PARAM_LENGTH, 2 * Consts.PACKET_SHORT_PARAM_LENGTH + dataLength);
        byte[] signature = Arrays.copyOfRange(responseData, 2 * Consts.PACKET_SHORT_PARAM_LENGTH + dataLength, 2 * Consts.PACKET_SHORT_PARAM_LENGTH + dataLength + sigLength);
        quorumsCtxMap.get(quorumIndex).pub_key_Hash = pubKeyHash;
        quorumsCtxMap.get(quorumIndex).retrieveCommitmentSignature = signature; // signature is verified after the public key is received
        return checkSW(response);
    }

    @Override
    public boolean StorePubKeyHash(short quorumIndex, short id,
                                   byte[] hash_arr, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_STORE_COMMITMENT, quorumIndex, id, (short) hash_arr.length);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_KEYGEN_STORE_COMMITMENT, hostPrivKey, (byte) 0x0, hostIndex, Util.concat(packetData, hash_arr));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    @Override
    public boolean StorePubKey(short quorumIndex, short id,
                               byte[] pub_arr, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_STORE_PUBKEY, quorumIndex, id, (short) pub_arr.length);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_KEYGEN_STORE_PUBKEY, hostPrivKey, (byte) 0x0, hostIndex, Util.concat(packetData, pub_arr));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    @Override
    public byte[] RetrievePubKey(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey, MPCGlobals mpcGlobals) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_RETRIEVE_PUBKEY, quorumIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_KEYGEN_RETRIEVE_PUBKEY, hostPrivKey, (byte) 0x0, hostIndex, packetData);
        ResponseAPDU response = transmit(channel, cmd);

        byte[] responseData = response.getData();
        byte[] data = Arrays.copyOfRange(responseData, 0, 65);
        short sigLen = Util.getShort(responseData, 65);
        byte[] signatue = Arrays.copyOfRange(responseData, 65 + 2, 65 + 2 + sigLen);

        quorumsCtxMap.get(quorumIndex).pubKey = Util.ECPointDeSerialization(mpcGlobals.curve, data , 0);  // Store Pub

        // set PublicKey object
        BigInteger x = quorumsCtxMap.get(quorumIndex).pubKey.normalize().getXCoord().toBigInteger();
        BigInteger y = quorumsCtxMap.get(quorumIndex).pubKey.normalize().getYCoord().toBigInteger();
        ECNamedCurveSpec params = new ECNamedCurveSpec("SecP256r1", mpcGlobals.curve, mpcGlobals.G, mpcGlobals.n);
        java.security.spec.ECPoint w = new java.security.spec.ECPoint(x, y);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        quorumsCtxMap.get(quorumIndex).pubkeyObject = keyFactory.generatePublic(new java.security.spec.ECPublicKeySpec(w, params));
        QuorumContext thisQContext = quorumsCtxMap.get(quorumIndex);

        // verifies INS_KEYGEN_RETRIEVE_PUBKEY signature
        if (!verifyECDSASignature(data, signatue, quorumsCtxMap.get(quorumIndex).pubkeyObject)) {
            quorumsCtxMap.get(quorumIndex).pubkeyObject = null;
            quorumsCtxMap.get(quorumIndex).pubKey = null;
            throw new SecurityException("Signature verification failed");
        }


        // verifies INS_KEYGEN_RETRIEVE_COMMITMENT signature
        if (!verifyECDSASignature(thisQContext.pub_key_Hash, thisQContext.retrieveCommitmentSignature, thisQContext.pubkeyObject)) {
            quorumsCtxMap.get(quorumIndex).pubkeyObject = null;
            quorumsCtxMap.get(quorumIndex).pubKey = null;
            throw new SecurityException("Signature verification failed");
        }

        return response.getData();
    }

    @Override
    public boolean RetrieveAggPubKey(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey)
            throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_RETRIEVE_AGG_PUBKEY, quorumIndex);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_KEYGEN_RETRIEVE_AGG_PUBKEY, hostPrivKey, (byte) 0x0, hostIndex, packetData);
        ResponseAPDU response = transmit(channel, cmd);
        byte[] responseData = response.getData();
        byte[] aggPubKey = parseAndVerifyPacket(responseData, quorumsCtxMap.get(quorumIndex).pubkeyObject);
        quorumsCtxMap.get(quorumIndex).AggPubKey = Util.ECPointDeSerialization(mpcGlobals.curve, aggPubKey, 0); // Store aggregated pub
        return checkSW(response);
    }

    @Override
    public byte[] Encrypt(short quorumIndex, byte[] plaintext, byte hostIndex, PrivateKey hostPrivKey)
            throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_ENCRYPT, quorumIndex, (short) plaintext.length);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_ENCRYPT, hostPrivKey, (byte) 0x0, hostIndex, Util.concat(packetData, plaintext));
        ResponseAPDU response = transmit(channel, cmd);
        return response.getData();
    }

    @Override
    public byte[] Decrypt(short quorumIndex, byte[] ciphertext, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        byte[] sharedSecret = performDHExchange(quorumIndex, hostIndex, hostPrivKey);

        byte[] packetData = preparePacketData(Consts.INS_DECRYPT, quorumIndex, (short) ciphertext.length);
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_DECRYPT, hostPrivKey, (byte) 0x0, hostIndex, Util.concat(packetData, ciphertext));
        ResponseAPDU response = transmit(channel, cmd);

        byte[] responseData = response.getData();
        // parse received packet to data and signature
        short dataLength = Util.getShort(responseData, 0);
        byte[] data = Arrays.copyOfRange(responseData, 0, 2 + dataLength + 16);
        short sigLen = Util.getShort(responseData, 2 + dataLength + 16);
        byte[] signature = Arrays.copyOfRange(responseData, 2 + dataLength + 16 + 2, 2 + dataLength + 16 + 2 + sigLen);
        if (!verifyECDSASignature(data, signature, quorumsCtxMap.get(quorumIndex).pubkeyObject)) {
            throw new GeneralSecurityException("Bogus packet signature.");
        }

        return decryptAes(data, sharedSecret);

    }

    /**
     * Decrypts aes cipher
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
    public BigInteger Sign(short quorumIndex, int round, byte[] Rn, byte[] plaintext, byte hostIndex, PrivateKey hostPrivKey) throws Exception {

        //String operationName = String.format("Signature(%s) (INS_SIGN)", msgToSign.toString());
        byte[] signature = Sign_plain(quorumIndex, round, plaintext, Rn, hostIndex, hostPrivKey);

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

    public byte[] Sign_plain(short quorumIndex, int round, byte[] plaintext, byte[] Rn, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_SIGN, quorumIndex, (short) round, (short) ((short) plaintext.length + (short) Rn.length));
        CommandAPDU cmd = GenAndSignPacket(Consts.INS_SIGN, hostPrivKey, (byte) round, hostIndex, Util.concat(packetData, Util.concat(plaintext, Rn)));
        ResponseAPDU response = transmit(channel, cmd);
        return response.getData();
    }

    private boolean checkSW(ResponseAPDU response) {
        if (response.getSW() != (Consts.SW_SUCCESS & 0xffff)) {
            System.err.printf("Received error status: %02X.\n",
                    response.getSW());
            assert !bFailOnAssert; // break on error
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
     * Parses packet and calls verifyECDSASignature()
     *
     * @param apdubuf received APDU buffer
     * @param pubkey  card's pubkey as PublicKey object
     * @return byte[] data part of the packet
     * @throws GeneralSecurityException if verifyECDSASignature fails
     */
    private byte[] parseAndVerifyPacket(byte[] apdubuf, PublicKey pubkey) throws GeneralSecurityException {
        short dataLength = Util.getShort(apdubuf, 0);
        short signatureLength = Util.getShort(apdubuf, 2);
        byte[] data = new byte[dataLength];
        System.arraycopy(apdubuf, 2 * 2, data, 0, dataLength);
        byte[] signature = new byte[signatureLength];
        System.arraycopy(apdubuf, 2 * 2 + dataLength, signature, 0, signatureLength);
        if (!verifyECDSASignature(data, signature, pubkey)) {
            throw new GeneralSecurityException("Bogus packet signature.");
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

    static class QuorumContext {

        public byte[] pub_key_Hash;
        public byte[] retrieveCommitmentSignature;
        short playerIndex;
        short quorumIndex = 0;
        short numPlayers = 0;
        BigInteger card_e_BI;
        ECPoint pubKey;
        PublicKey pubkeyObject;
        ECPoint AggPubKey;
        Bignat requestCounter;


        QuorumContext(short quorumIndex, short playerIndex, short numPlayers) {
            this.quorumIndex = quorumIndex;
            this.playerIndex = playerIndex;
            this.numPlayers = numPlayers;
            requestCounter = new Bignat((short) 2, false);
            requestCounter.zero();
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
