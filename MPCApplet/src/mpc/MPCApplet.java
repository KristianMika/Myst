package mpc;

import javacard.framework.*;
import mpc.jcmathlib.ECConfig;
import mpc.jcmathlib.ECCurve;
import mpc.jcmathlib.SecP256r1;


/**
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class MPCApplet extends Applet {
    static boolean bIsSimulator = false;    // if true, applet is running in simulator. Detection Required for certain operations where simulator differs from real card
    public byte[] cardIDLong = null; // unique card ID generated during the applet install
    ECConfig m_ecc;

    // TODO: Every card can participate in multiple quorums => QuorumContext[]. For preventive security reasons, number of QuorumContexts can be 1 => no overlapping of protocols
    // TODO: Every quorum can be executing different protocol (keygen, enc, dec, sign, rng) - allow only one running protocol at the time for given quorum
    // TODO: Enable/disable propagation of private key to other quorum
    // TODO: Generate unique card key for signatures
    // TODO: Unify response codes
    // TODO: Remove IS_BACKDOORED_EXAMPLE
    // TODO: remove boolean variables
    // TODO: Rename Bignat variables
    // TODO: unify all member attributes under m_xxx naming and camelCase
    ECCurve m_curve;
    MPCCryptoOps m_cryptoOps = null;
    QuorumContext[] m_quorums = null;
    private short exceptionCount;
    private boolean isAppletLocked;

    public MPCApplet() {
        m_ecc = new ECConfig((short) 256);
        m_ecc.bnh.bIsSimulator = bIsSimulator;
        m_curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);

        ECPointBuilder.allocate(m_curve, m_ecc);
        ECPointBase.allocate(m_curve);
        if (m_ecc.MULT_RSA_ENGINE_MAX_LENGTH_BITS < (short) 1024) {
            ISOException.throwIt(Consts.SW_INCORRECTJCMATHLIBSETTINGS);
        }

        m_cryptoOps = new MPCCryptoOps(m_ecc);

        m_quorums = new QuorumContext[Consts.MAX_QUORUMS];
        for (short i = 0; i < (short) m_quorums.length; i++) {
            m_quorums[i] = new QuorumContext(m_ecc, m_curve, m_cryptoOps, i);
        }

        // Generate random unique card ID
        cardIDLong = new byte[Consts.CARD_ID_LONG_LENGTH];
        m_cryptoOps.randomData.generateData(cardIDLong, (short) 0, (short) cardIDLong.length);

        exceptionCount = 0;
        isAppletLocked = false;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // GP-compliant JavaCard applet registration
        if (bLength == 0) {
            // Simulator provides no install params
            bIsSimulator = true;
            new MPCApplet().register();
        } else {
            new MPCApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
        }
    }

    public boolean select() {
        updateAfterReset();
        Quorum_ResetAll();
        return true;
    }

    // ////////////////////////////////////////////////////////////////////////////////////

    public void process(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        if (selectingApplet()) {
            return;
        }

        if (isAppletLocked) {
            ISOException.throwIt(Consts.SW_APPLET_LOCKED);
        }

        if (apdubuf[ISO7816.OFFSET_CLA] != Consts.CLA_MPC) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        exceptionCount += 1;
        try {
            switch (apdubuf[ISO7816.OFFSET_INS]) {
                case Consts.INS_PERF_SETSTOP:
                    PM.m_perfStop = Util.makeShort(apdubuf[ISO7816.OFFSET_CDATA], apdubuf[(short) (ISO7816.OFFSET_CDATA + 1)]);
                    break;

                //
                // Card bootstrapping
                //
                case Consts.INS_PERSONALIZE_INITIALIZE:
                    // Generates initial secrets, set user authorization info and export card's public key
                    Personalize_Init(apdu);
                    break;

                case Consts.INS_PERSONALIZE_SET_USER_AUTH_PUBKEY:
                    // Set public key later used to authorize requests
                    Personalize_SetUserAuthPubKey(apdu);
                    break;

                case Consts.INS_PERSONALIZE_GETCARDINFO:
                    Personalize_GetCardInfo(apdu);
                    break;

                //
                // Quorum Management
                //
                case Consts.INS_QUORUM_SETUP_NEW:
                    // Includes this card into new quorum (QuorumContext[i])
                    Quorum_SetupNew(apdu);
                    break;
                case Consts.INS_QUORUM_REMOVE:
                    // Removes this card from existing quorum and cleanup quorum context (QuorumContext[i])
                    Quorum_Remove(apdu);
                    break;
                case Consts.INS_QUORUM_RESET:
                    // Reset all sensitive values in specified quorum (but keeps quorum settings)
                    Quorum_Reset(apdu);
                    break;


                //
                // Key Generation
                //
                case Consts.INS_KEYGEN_INIT:
                    KeyGen_Init(apdu);
                    break;
                case Consts.INS_KEYGEN_RETRIEVE_COMMITMENT:
                    KeyGen_RetrieveCommitment(apdu);
                    break;
                case Consts.INS_KEYGEN_STORE_COMMITMENT:
                    KeyGen_StoreCommitment(apdu);
                    break;
                case Consts.INS_KEYGEN_RETRIEVE_PUBKEY:
                    KeyGen_RetrievePublicKey(apdu);
                    break;
                case Consts.INS_KEYGEN_STORE_PUBKEY:
                    KeyGen_StorePublicKey(apdu);
                    break;
                case Consts.INS_KEYGEN_RETRIEVE_AGG_PUBKEY:
                    KeyGen_RetrieveAggregatedPublicKey(apdu);
                    break;

                //
                // Key propagation to other quorums
                //
                case Consts.INS_KEYPROPAGATION_RETRIEVE_PRIVKEY_SHARES:
                    KeyMove_RetrievePrivKeyShares(apdu);
                    break;
                case Consts.INS_KEYPROPAGATION_SET_PRIVKEY_SHARES:
                    KeyMove_SetPrivKeyShares(apdu);
                    break;
                case Consts.INS_KEYPROPAGATION_RECONSTRUCT_PRIVATEKEY:
                    KeyMove_ReconstructPrivateKey(apdu);
                    break;


                //
                // Encrypt and decrypt
                //
                case Consts.INS_ENCRYPT:
                    EncryptData(apdu);
                    break;
                case Consts.INS_DECRYPT:
                    DecryptData(apdu);
                    break;
                case Consts.INS_ECDH_EXCHANGE:
                    ExchangeKey(apdu);
                    break;

                //
                // Signing
                //
                case Consts.INS_SIGN_RETRIEVE_RI:
                    Sign_RetrieveRandomRi(apdu);
                    break;
                case Consts.INS_SIGN_INIT:
                    SignInit(apdu);
                    break;
                case Consts.INS_SIGN:
                    Sign(apdu);
                    break;
                case Consts.INS_SIGN_GET_CURRENT_COUNTER:
                    Sign_GetCurrentCounter(apdu);
                    break;

                //
                // Random number generation
                //
                case Consts.INS_GENERATE_RANDOM:
                    GenerateRandomData(apdu);
                    break;


                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
            exceptionCount -= 1;
        }
        catch (ISOException e) {
            if (exceptionCount >= Consts.EXCEPTION_COUNT_LIMIT) {
                LockApplet();
            }

            ISOException.throwIt(e.getReason());
        }
        catch (Exception e) {
            if (exceptionCount >= Consts.EXCEPTION_COUNT_LIMIT) {
                LockApplet();
            }

            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    void updateAfterReset() {
        if (m_curve != null) {
            m_curve.updateAfterReset();
        }
        if (m_ecc != null) {
            m_ecc.refreshAfterReset();
            m_ecc.unlockAll();
        }
        if (m_ecc.bnh != null) {
            m_ecc.bnh.bIsSimulator = bIsSimulator;
        }
    }

    /**
     * Returns target quorum based on info from input apdu
     *
     * @param apdubuf
     * @param paramsStartOffset
     * @return
     */
    QuorumContext GetTargetQuorumContext(byte[] apdubuf, short paramsStartOffset) {
        short ctxIndex = Util.getShort(apdubuf, (short) (paramsStartOffset + Consts.PACKET_PARAMS_CTXINDEX_OFFSET));
        if (ctxIndex < 0 || ctxIndex >= (short) m_quorums.length) ISOException.throwIt(Consts.SW_INVALIDQUORUMINDEX);
        return m_quorums[ctxIndex];
    }


    short GetOperationParamsOffset(byte operationCode, APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.getIncomingLength();
        // Check correctness of basic structure and expected operation
        short offset = ISO7816.OFFSET_CDATA;
        if (apdubuf[offset] != Consts.TLV_TYPE_MPCINPUTPACKET) ISOException.throwIt(Consts.SW_INVALIDPACKETSTRUCTURE);
        offset++;
        short packetLen = Util.getShort(apdubuf, offset);
        if (packetLen < 1 || packetLen > dataLen)
            ISOException.throwIt(Consts.SW_INVALIDPACKETSTRUCTURE); // at least 1 byte of packet content required for operationCode
        offset += 2;
        if (apdubuf[offset] != operationCode) ISOException.throwIt(Consts.SW_INVALIDPACKETSTRUCTURE);

        return offset;
    }

    /**
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B - numPlayers | 2B - thisPlayerIndex|
     * <HOST_ID_SIZE>B host's ID | signature
     * Outgoing packet: response code
     *
     * @apdu
     */
    void Quorum_SetupNew(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        short paramsOffset = GetOperationParamsOffset(Consts.INS_QUORUM_SETUP_NEW, apdu);

        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        // setup is called before host's pubkey and ACL is set up
        if (quorumCtx.host_count > 0) {
            verifySignature(apdubuf, quorumCtx, (short) (paramsOffset + Consts.PACKET_PARAMS_SETUPNEWQUORUM_SIGNATURE_OFFSET),
                    (short) (paramsOffset + Consts.PACKET_PARAMS_SETUPNEWQUORUM_HOSTID_OFFSET));

            short hostIndex = quorumCtx.FindHost(apdubuf, Consts.PACKET_PARAMS_SETUPNEWQUORUM_HOSTID_OFFSET);

            quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_SetupNew, hostIndex);
        }

        // Extract function parameters
        short numPlayers = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SETUPNEWQUORUM_NUMPLAYERS_OFFSET));
        short thisPlayerIndex = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SETUPNEWQUORUM_THISPLAYERINDEX_OFFSET));
        quorumCtx.SetupNew(numPlayers, thisPlayerIndex);
    }

    /**
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | signature
     * Outgoing packet: response code
     *
     * @param apdu
     */
    void Quorum_Remove(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        short paramsOffset = GetOperationParamsOffset(Consts.INS_QUORUM_REMOVE, apdu);

        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        verifySignature(apdubuf, quorumCtx, (short) (paramsOffset + Consts.PACKET_PARAMS_REMOVEQUORUM_SIGNATURE_OFFSET),
                (short) (paramsOffset + Consts.PACKET_PARAMS_REMOVEQUORUM_HOSTID_OFFSET));

        short hostIndex = quorumCtx.FindHost(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_REMOVEQUORUM_HOSTID_OFFSET));

        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_GenerateRandomData, hostIndex);

        quorumCtx.Reset();

        // TODO: mark context free for next Quorum_SetupNew() call
    }

    /**
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | signature
     * Outgoing packet: response code
     *
     * @param apdu
     */
    void Quorum_Reset(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        short paramsOffset = GetOperationParamsOffset(Consts.INS_QUORUM_RESET, apdu);

        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        if (quorumCtx.host_count > 0) {
            verifySignature(apdubuf, quorumCtx, (short) (paramsOffset + Consts.PACKET_PARAMS_QUORUMRESET_SIGNATURE_OFFSET),
                    (short) (paramsOffset + Consts.PACKET_PARAMS_QUORUMRESET_HOSTID_OFFSET));

            short hostIndex = quorumCtx.FindHost(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_QUORUMRESET_HOSTID_OFFSET));

            quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_Reset, hostIndex);
        }

        // Reset target quorum context    
        quorumCtx.Reset();
    }

    /**
     * Resets all quorums and sets the isAppletLocked boolean.
     * TODO: Use mechanisms designed for locking applets
     */
    private void LockApplet() {
        Quorum_ResetAll();
        isAppletLocked = true;
    }

    /**
     * Reset all quorum from QuorumContext[]
     */
    private void Quorum_ResetAll() {
        for (short i = 0; i < (short) m_quorums.length; i++) {
            m_quorums[i].Reset();
        }
    }

    void Personalize_Init(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.getIncomingLength();

        // TODO: check state
        // TODO: check authorization
        // TODO: generate card long-term signature key
        // TODO: clear QuorumContext[] 
        // TODO: change state
        // TODO: export card public info
    }

    /**
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B host's permissions | <HOST_ID_SIZE>B host's ID |
     * pubKey | signature
     * Outgoing packet: response code
     *
     * @param apdu
     */

    void Personalize_SetUserAuthPubKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.getIncomingLength();

        short paramsOffset = GetOperationParamsOffset(Consts.INS_PERSONALIZE_SET_USER_AUTH_PUBKEY, apdu);

        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        if (quorumCtx.host_count > 0) {
            verifySignature(apdubuf, quorumCtx, (short) (paramsOffset + Consts.PACKET_PARAMS_SETUSERAUTHPUBKEY_SIGNATURE_OFFSET),
                    (short) (paramsOffset + Consts.PACKET_PARAMS_SETUSERAUTHPUBKEY_HOSTID_OFFSET));

            short hostIndex = quorumCtx.FindHost(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SETUSERAUTHPUBKEY_HOSTID_OFFSET));

            quorumCtx.VerifyCallerAuthorization(StateModel.FNC_INS_PERSONALIZE_SET_USER_AUTH_PUBKEY, hostIndex);
        }

        quorumCtx.SetUserAuthPubkey(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SETUSERAUTHPUBKEY_PUBKEY_OFFSET),
                (short) (paramsOffset + Consts.PACKET_PARAMS_SETUSERAUTHPUBKEY_PERM_OFFSET));

        // TODO: change state
        // TODO: export card public info
    }


    void Personalize_GetCardInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();


        short offset = 0;

        buffer[offset] = Consts.TLV_TYPE_CARDUNIQUEDID;
        offset++;
        Util.setShort(buffer, offset, (short) cardIDLong.length);
        offset += 2;
        Util.arrayCopyNonAtomic(cardIDLong, (short) 0, buffer, offset, (short) cardIDLong.length);
        offset += cardIDLong.length;

        buffer[offset] = Consts.TLV_TYPE_KEYPAIR_STATE;
        offset++;
        Util.setShort(buffer, offset, (short) 2);
        offset += 2;
        Util.setShort(buffer, offset, m_quorums[0].GetState()); // TODO: read states from all quorums
        offset += 2;

        buffer[offset] = Consts.TLV_TYPE_EPHIMERAL_STATE;
        offset++;
        Util.setShort(buffer, offset, (short) 2);
        offset += 2;
        //Util.setShort(buffer, offset, CryptoObjects.EphimeralKey.getState()); // TODO: read states from all quorums
        offset += 2;

        // Available memory
        buffer[offset] = Consts.TLV_TYPE_MEMORY;
        offset++;
        Util.setShort(buffer, offset, (short) 6);
        offset += 2;
        Util.setShort(buffer, offset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
        offset += 2;
        Util.setShort(buffer, offset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
        offset += 2;
        Util.setShort(buffer, offset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
        offset += 2;

        // Used compile-time switches
        buffer[offset] = Consts.TLV_TYPE_COMPILEFLAGS;
        offset++;
        Util.setShort(buffer, offset, (short) 4);
        offset += 2;
        Util.setShort(buffer, offset, Consts.MAX_NUM_PLAYERS);
        offset += 2;
        buffer[offset] = Consts.PLAYERS_IN_RAM ? (byte) 1 : (byte) 0;
        offset++;
        buffer[offset] = Consts.COMPUTE_Y_ONTHEFLY ? (byte) 1 : (byte) 0;
        offset++;

        // Git commit tag
        buffer[offset] = Consts.TLV_TYPE_GITCOMMIT;
        offset++;
        Util.setShort(buffer, offset, (short) 4);
        offset += 2;
        Util.arrayCopyNonAtomic(Consts.GIT_COMMIT_MANUAL, (short) 0, buffer, offset, (short) Consts.GIT_COMMIT_MANUAL.length);
        offset += (short) Consts.GIT_COMMIT_MANUAL.length;

        // Flag about example demonstartion of beckdoored behavior
        buffer[offset] = Consts.TLV_TYPE_EXAMPLEBACKDOOR;
        offset++;
        Util.setShort(buffer, offset, (short) 1);
        offset += 2;
        buffer[offset] = Consts.IS_BACKDOORED_EXAMPLE ? (byte) 1 : (byte) 0;
        offset += 1;

        apdu.setOutgoingAndSend((short) 0, offset);
    }

    /**
     * Set trusted hashes of public keys for all other cards that may eventually
     * take part in protocol. Used to quickly verify provided player's public key
     * during the protocol run
     *
     * @param apdu
     */
    void SetTrustedPubKeyHashes(APDU apdu) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        // TODO
    }

    /**
     * At the first step of the protocol, each member of Q runs Algorithm 4.1 and generates
     * a triplet consisting of: 1) a share xi , which is a randomly sampled
     * element from Zn, 2) an elliptic curve point Yi , and 3) a commitment
     * to Yi denoted hi.
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | nonce | signature
     * Outgoing packet: 2B nonce length | card's nonce | 2B signature length | signature
     *
     * @param apdu
     */
    void KeyGen_Init(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYGEN_INIT, apdu);

        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        verifySignature(apdubuf, quorumCtx, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENINIT_SIGNATURE_OFFSET),
                (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENINIT_HOSTID_OFFSET));

        short hostIndex = quorumCtx.FindHost(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENINIT_HOSTID_OFFSET));

        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_InitAndGenerateKeyPair, hostIndex);

        // Generate new triplet
        quorumCtx.InitAndGenerateKeyPair(true);

        // create the outgoing packet
        short len = createOutgoingSuccessApdu(apdubuf, quorumCtx,
                (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENINIT_NONCE_OFFSET));

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Upon the generation of the triplet, the members perform a pairwise
     * exchange of their commitments. KeyGen_RetrieveCommitment returns commitment for this card
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | signature
     * Outgoing packet: 2B - data length | data (commitment) | 2B - signature length | signature
     *
     * @param apdu
     */
    void KeyGen_RetrieveCommitment(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYGEN_RETRIEVE_COMMITMENT, apdu);

        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        verifySignature(apdubuf, quorumCtx, (short) (paramsOffset + Consts.PACKET_PARAMS_RETRIEVECOMMITMENT_IN_SIGNATURE_OFFSET),
                (short) (paramsOffset + Consts.PACKET_PARAMS_RETRIEVECOMMITMENT_IN_HOSTID_OFFSET));

        short hostIndex = quorumCtx.FindHost(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_RETRIEVECOMMITMENT_IN_HOSTID_OFFSET));

        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_RetrieveCommitment, hostIndex);

        // Obtain commitment for this card
        short len = quorumCtx.RetrieveCommitment(apdubuf, Consts.PACKET_PARAMS_RETRIEVECOMMITMENT_OUT_DATA_OFFSET);

        // set the data length parameter
        Util.setShort(apdubuf, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET, len);
        len += Consts.SHORT_SIZE;

        len += quorumCtx.signApdu(apdubuf, len);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Upon the generation of the triplet, the members perform a pairwise
     * exchange of their commitments by the end of which, they all hold a
     * set H = {h1,h2, ..,ht }. The commitment exchange terminates when |Hq | =
     * t ∀q ∈ Q
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B - player's index| 2B hash length |
     * <HOST_ID_SIZE>B host's ID | nonce | hash | signature
     * Outgoing packet: 2B nonce length | card's nonce | 2B signature length | signature
     *
     * @param apdu
     */
    void KeyGen_StoreCommitment(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.getIncomingLength();

        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYGEN_STORE_COMMITMENT, apdu);

        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        short playerId = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTORECOMMITMENT_PLAYERID_OFFSET));
        short commitmentLen = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTORECOMMITMENT_COMMITMENTLENGTH_OFFSET));

        verifySignature(apdubuf, quorumCtx, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTORECOMMITMENT_COMMITMENT_OFFSET + commitmentLen),
                (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTORECOMMITMENT_HOSTID_OFFSET));

        short hostIndex = quorumCtx.FindHost(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTORECOMMITMENT_HOSTID_OFFSET));

        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_StoreCommitment, hostIndex);

        // Store provided commitment
        quorumCtx.StoreCommitment(playerId, apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTORECOMMITMENT_COMMITMENT_OFFSET),
                commitmentLen);

        len = createOutgoingSuccessApdu(apdubuf, quorumCtx,
                (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTORECOMMITMENT_NONCE_OFFSET));

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Another round of exchanges starts (KeyGen_RetrievePublicKey and KeyGen_StorePublicKey), this time for the shares of Yagg
     * The commitment exchange round (KeyGen_RetrieveCommitment and KeyGen_StoreCommitment) is of uttermost
     * importance as it forces the participants to commit to a share of Yagg, before receiving the shares of others.
     * This prevents attacks where an adversary first collects the shares of others, and then crafts its share so as to bias the final pair,
     * towards a secret key they know.
     * Outgoing packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | signature
     * Incoming packet: 2B data length | 65B data (PubKey) | 2B signature length | signature
     *
     * @param apdu
     */
    void KeyGen_RetrievePublicKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYGEN_RETRIEVE_PUBKEY, apdu);

        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        verifySignature(apdubuf, quorumCtx, (short) (paramsOffset + Consts.PACKET_PARAMS_RETRIEVEPUBKEY_IN_SIGNATURE_OFFSET),
                (short) (paramsOffset + Consts.PACKET_PARAMS_RETRIEVEPUBKEY_IN_HOSTID_OFFSET));

        short hostIndex = quorumCtx.FindHost(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_RETRIEVEPUBKEY_IN_HOSTID_OFFSET));

        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_GetYi, hostIndex);

        // Retrieve public key
        short len = quorumCtx.GetYi(apdubuf, Consts.PACKET_PARAMS_RETRIEVEPUBKEY_OUT_DATA_OFFSET);
        Util.setShort(apdubuf, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET, len);

        len += 2;
        len += quorumCtx.signApdu(apdubuf, len);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Verify the validity of Y’s elements against their previous commitments KeyGen_StoreCommitment().
     * If one or more commitments fail the verification then the member infers that an error (either intentional or
     * unintentional) occurred and the protocol is terminated.
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B - player's index| 2B key length |
     * <HOST_ID_SIZE>B host's ID | nonce | key | signature
     * Outgoing packet: 2B nonce length | card's nonce | 2B signature length | signature
     *
     * @param apdu
     */
    void KeyGen_StorePublicKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.getIncomingLength();

        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYGEN_STORE_PUBKEY, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        short playerId = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTOREPUBKEY_PLAYERID_OFFSET));
        short pubKeyLen = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTOREPUBKEY_PUBKEYLENGTH_OFFSET));

        verifySignature(apdubuf, quorumCtx, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTOREPUBKEY_PUBKEY_OFFSET + pubKeyLen),
                (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTOREPUBKEY_HOSTID_OFFSET));

        short hostIndex = quorumCtx.FindHost(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTOREPUBKEY_HOSTID_OFFSET));

        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_SetYs, hostIndex);

        // Store provided public key
        quorumCtx.SetYs(playerId, apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTOREPUBKEY_PUBKEY_OFFSET), pubKeyLen);

        len = createOutgoingSuccessApdu(apdubuf, quorumCtx,
                (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTOREPUBKEY_NONCE_OFFSET));

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * If all commitments are successfully verified, then the member executes
     * Algorithm 4.3 and returns the result to the remote host. Note
     * that it is important to return Yagg, as well as the individual shares Yi
     * , as this protects against integrity attacks, where malicious ICs return
     * a different share than the one they committed to during the protocol.
     * Moreover, since Yi are shares of the public key, they are also
     * assumed to be public, and available to any untrusted party.
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | signature
     * Outgoing packet: 2B - data length | data (Yagg) | signature
     */
    void KeyGen_RetrieveAggregatedPublicKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYGEN_RETRIEVE_AGG_PUBKEY, apdu);

        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        verifySignature(apdubuf, quorumCtx, (short) (paramsOffset + Consts.PACKET_PARAMS_RETRIEVEYAGG_IN_SIGNATURE_OFFSET),
                (short) (paramsOffset + Consts.PACKET_PARAMS_RETRIEVEYAGG_IN_HOSTID_OFFSET));

        short hostIndex = quorumCtx.FindHost(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_RETRIEVEYAGG_IN_HOSTID_OFFSET));

        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_GetY, hostIndex);

        // Retrieve aggregated pubic key
        short len = quorumCtx.GetY().getW(apdubuf, Consts.PACKET_PARAMS_RETRIEVEYAGG_OUT_DATA_OFFSET);

        // set the data length parameter
        Util.setShort(apdubuf, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET, len);
        len += Consts.SHORT_SIZE;

        len += quorumCtx.signApdu(apdubuf, len);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Each member qi of Q1 then splits its secret xi in |Q2 | shares and
     * distributes them to the individual members of Q2. To do that qi follows
     * the secret sharing method shown in Algorithm 4.8. However, any t -of-t
     * secret sharing schemes proposed in the literature would do.
     *
     * @param apdu
     */
    void KeyMove_RetrievePrivKeyShares(APDU apdu) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);

        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYPROPAGATION_RETRIEVE_PRIVKEY_SHARES, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        // TODO: Check state
        // TODO: split y into shares for other quorum
        // TODO: Switch into next state
        // apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Once each member of Q2 receives |Q1 | shares, which they then combine to
     * retrieve their share of the secret corresponding to y. Each member of Q2
     * can retrieve its share by summing the incoming shares, modulo p (the
     * prime provided in the domain parameters T ). An additional benefit of
     * such a scheme is that Q1 and Q2 may have different sizes. It should be
     * also noted that a naive approach of having each member of q1 send their
     * share of x to a member of q2 is insecure, as malicious members from q1
     * and q2 can then collude to reconstruct the public key.
     *
     * @param apdu
     */
    void KeyMove_SetPrivKeyShares(APDU apdu) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);

        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYPROPAGATION_SET_PRIVKEY_SHARES, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        // TODO: Check state
        // TODO: Combine all shares to restore secret key y
        // TODO: Switch into next state
        // TODO: VERIFY PACKET SIGNATURE
        //apdu.setOutgoingAndSend((short) 0, len);
    }

    void KeyMove_ReconstructPrivateKey(APDU apdu) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);

        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYPROPAGATION_RECONSTRUCT_PRIVATEKEY, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        // TODO: Check state
        // TODO: Combine all shares to restore secret key y
        // TODO: Switch into next state
        // TODO: VERIFY PACKET SIGNATURE
        //apdu.setOutgoingAndSend((short) 0, len);
    }


    /**
     * For encryption, we use the Elliptic Curve ElGamal scheme
     * (Algorithm 4.4). This operation does not use the secret key, and can be
     * performed directly on the host, or remotely by any party holding the
     * public key, hence there is no need to perform it in a distributed manner.
     *
     * @param apdu Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B plaintext length |
     *                              <HOST_ID_SIZE>B host's ID | plaintext | signature
     *             Outgoing packet: 2B - cipher length | xB cipher | 2B sigLen | yB signature
     */
    void EncryptData(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_ENCRYPT, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        short dataLen = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_ENCRYPT_IN_DATALENGTH_OFFSET));

        short hostIdOff = (short) (paramsOffset + Consts.PACKET_PARAMS_ENCRYPT_IN_HOSTID_OFFSET);

        // Verify packet signature
        verifySignature(apdubuf, quorumCtx, (short) (hostIdOff + Consts.HOST_ID_SIZE + dataLen), hostIdOff);

        // Verify authorization
        short hostIndex = quorumCtx.FindHost(apdubuf, hostIdOff);
        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_Encrypt, hostIndex);

        dataLen = quorumCtx.Encrypt(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_ENCRYPT_IN_DATA_OFFSET),
                dataLen, apdubuf, Consts.PACKET_PARAMS_ENCRYPT_OUT_CIPHER_OFFSET);

        Util.setShort(apdubuf, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET, dataLen);
        dataLen += Consts.SHORT_SIZE;

        dataLen += quorumCtx.signApdu(apdubuf, dataLen);

        apdu.setOutgoingAndSend((short) 0, dataLen);
    }

    /**
     * Distributed data decryption (Algorithm 4.5). All KeyGen_xxx must be executed before.
     * Incoming packet: 2B cipher length | xB cipher | 16B IV | 2B signature length | yB signature
     *
     * @param apdu Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B cipher length | <HOST_ID_SIZE>B host's ID | cipher | signature
     *             Outgoing packet: 2B data length | E_EphemKey(data)| IV | 2B signature Length | signature
     */
    void DecryptData(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_DECRYPT, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        short dataLen = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_DECRYPT_IN_DATALENGTH_OFFSET));


        //Verify packet signature
        verifySignature(apdubuf, quorumCtx, (short) (paramsOffset + Consts.PACKET_PARAMS_DECRYPT_IN_DATA_OFFSET + dataLen),
                (short) (paramsOffset + Consts.PACKET_PARAMS_DECRYPT_IN_HOSTID_OFFSET));

        // Verify authorization - is caller allowed to ask for decryption?
        short hostIndex = quorumCtx.FindHost(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_DECRYPT_IN_HOSTID_OFFSET));
        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_DecryptShare, hostIndex);

        byte[] encryptBuffer = new byte[256];
        dataLen = quorumCtx.DecryptShare(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_DECRYPT_IN_DATA_OFFSET), dataLen, encryptBuffer);

        dataLen = quorumCtx.EncryptUsingAES(encryptBuffer, (short) 0, dataLen, apdubuf, Consts.PACKET_PARAMS_DECRYPT_OUT_DATA_OFFSET);

        Util.setShort(apdubuf, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET, dataLen);
        dataLen += Consts.SHORT_SIZE;

        dataLen += quorumCtx.signApdu(apdubuf, dataLen);

        apdu.setOutgoingAndSend((short) 0, dataLen);
    }

    /**
     * Exchanges and computes ephemeral key using Diffie Hellman key exchange scheme.
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B - host's key part length | <HOST_ID_SIZE>B host's ID | host's key part |  signature
     * Outgoing packet: 2B data length | data | 2B signature length | signature
     *
     * @param apdu
     */
    // TODO: verify caller authorisation
    void ExchangeKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_ECDH_EXCHANGE, apdu);
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        short dataLength = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_EXCHANGEKEY_IN_KEYLENGTH_OFFSET));

        verifySignature(apdubuf, quorumCtx, (short) (paramsOffset + Consts.PACKET_PARAMS_EXCHANGEKEY_IN_HOSTKEY_OFFSET + dataLength),
                (short)(paramsOffset + Consts.PACKET_PARAMS_EXCHANGEKEY_IN_HOSTID_OFFSET));

        short len = quorumCtx.exchangeKey(apdubuf,
                (short) (paramsOffset + Consts.PACKET_PARAMS_EXCHANGEKEY_IN_HOSTKEY_OFFSET), dataLength,
                apdubuf, Consts.PACKET_PARAMS_EXCHANGEKEY_OUT_CARDKEY_OFFSET);

        Util.setShort(apdubuf, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET, len);
        len += Consts.SHORT_SIZE;

        len += quorumCtx.signApdu(apdubuf, len);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * First part of distributed signature scheme (Algorithm 4.7). All KeyGen_xxx must be executed
     * before.
     *
     * @apdu input apdu
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B short i | <HOST_ID_SIZE>B host's ID | signature
     * Outgoing packet: 2B data Length | data | 2B signature Length | signature
     */
    void Sign_RetrieveRandomRi(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_SIGN_RETRIEVE_RI, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        short hostIdOf = (short) (paramsOffset + Consts.PACKET_PARAMS_SIGNRETRIEVERI_IN_HOSTID_OFFSET);
        // Verify packet signature
        verifySignature(apdubuf, quorumCtx, (short) (hostIdOf + Consts.HOST_ID_SIZE), hostIdOf);
        short hostIdIndex = quorumCtx.FindHost(apdubuf, hostIdOf);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_Sign_RetrieveRandomRi, hostIdIndex);

        short counter = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SIGNRETRIEVERI_IN_COUNTER_OFFSET));

        short dataLen = quorumCtx.Sign_RetrieveRandomRi(counter, apdubuf, Consts.PACKET_PARAMS_SIGNRETRIEVERI_OUT_DATA_OFFSET);
        Util.setShort(apdubuf, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET, dataLen);

        dataLen += Consts.SHORT_SIZE;
        dataLen += quorumCtx.signApdu(apdubuf, dataLen);

        apdu.setOutgoingAndSend((short) 0, dataLen);
    }

    
    void SignInit(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_SIGN_INIT, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        short dataLen = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SIGN_IN_DATALENGTH_OFFSET));
        short hostIdOff = (short) (paramsOffset + Consts.PACKET_PARAMS_SIGN_IN_HOSTID_OFFSET);
        //Verify packet signature
        
        // verifySignature(apdubuf, quorumCtx, (short) (hostIdOff + Consts.HOST_ID_SIZE + dataLen), hostIdOff);
        // Verify authorization

        //quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_Sign, quorumCtx.FindHost(apdubuf, hostIdOff));

        m_cryptoOps.temp_sign_counter.from_byte_array((short) 2, (short) 0, apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SIGN_IN_COUNTER_OFFSET));
        dataLen = quorumCtx.SignInit(m_cryptoOps.temp_sign_counter, apdubuf, Consts.PACKET_PARAMS_SIGN_OUT_DATA_OFFSET);

        Util.setShort(apdubuf, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET, dataLen);
        dataLen += Consts.SHORT_SIZE;

        dataLen += quorumCtx.signApdu(apdubuf, dataLen);

        apdu.setOutgoingAndSend((short) 0, dataLen);
    }
    
    /**
     * Second part of distributed signature scheme (Algorithm 4.7). All
     * KeyGen_xxx must be executed before.
     *
     * @apdu input data
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B - round | 2B plaintext + Rn length | <HOST_ID_SIZE>B host's ID | plaintext | Rn | signature
     * Outgoing packet: 2B Signature Length | XB signature | 2B APDU signature length | APDU signature
     */
    void Sign(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_SIGN, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        short dataLen = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SIGN_IN_DATALENGTH_OFFSET));
        short hostIdOff = (short) (paramsOffset + Consts.PACKET_PARAMS_SIGN_IN_HOSTID_OFFSET);

        //Verify packet signature
        verifySignature(apdubuf, quorumCtx, (short) (hostIdOff + Consts.HOST_ID_SIZE + dataLen), hostIdOff);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_Sign, quorumCtx.FindHost(apdubuf, hostIdOff));

        m_cryptoOps.temp_sign_counter.from_byte_array((short) 2, (short) 0, apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SIGN_IN_COUNTER_OFFSET));
        dataLen = quorumCtx.Sign(m_cryptoOps.temp_sign_counter, apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SIGN_IN_DATA_OFFSET),
                dataLen, apdubuf, Consts.PACKET_PARAMS_SIGN_OUT_DATA_OFFSET);

        Util.setShort(apdubuf, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET, dataLen);
        dataLen += Consts.SHORT_SIZE;

        dataLen += quorumCtx.signApdu(apdubuf, dataLen);

        apdu.setOutgoingAndSend((short) 0, dataLen);
    }

    /**
     * Returns the current signature counter.
     *
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | <HOST_ID_SIZE>B host's ID | signature
     * Outgoing packet: 2B counter length | counter | 2B signature length | signature
     * @param apdu
     */
    void Sign_GetCurrentCounter(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_SIGN_GET_CURRENT_COUNTER, apdu);

        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        short hostIdOff = (short) (paramsOffset + Consts.PACKET_PARAMS_GETCURRENTCOUNTER_IN_HOSTID_OFFSET);

        verifySignature(apdubuf, quorumCtx,
                (short) (paramsOffset + Consts.PACKET_PARAMS_GETCURRENTCOUNTER_IN_SIGNATURE_OFFSET), hostIdOff);

        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_Sign_GetCurrentCounter, quorumCtx.FindHost(apdubuf, hostIdOff));

        short dataLen = quorumCtx.Sign_GetCurrentCounter(apdubuf, Consts.PACKET_PARAMS_GETCURRENTCOUNTER_OUT_COUNTER_OFFSET);
        Util.setShort(apdubuf, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET, dataLen);

        dataLen += Consts.SHORT_SIZE;
        dataLen += quorumCtx.signApdu(apdubuf, dataLen);

        apdu.setOutgoingAndSend((short) 0, dataLen);
    }


    /**
     * The remote host submits a request for randomness to all actors
     * participating in the quorum. Subsequently, each actor independently
     * generates a random share bi , encrypts it with the public key of the
     * host, and signs the ciphertext with its private key. Once the host
     * receives all the shares, he combines them to retrieve the b and then uses
     * an one way function (e.g., SHA3-512) to convert it to a fixed length
     * string.
     * Incoming packet: 1B - op code | 2B - short 4 | 2B - quorum_i | 2B - num of bytes | <HOST_ID_SIZE>B host's ID | signature
     * Outgoing packet: 2B data length | E_EphemKey(random_bytes) | IV | 2B signature length | signature
     */
    void GenerateRandomData(APDU apdu) {

        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_GENERATE_RANDOM, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        short numOfBytes = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_GENERATERANDOM_IN_LENGTH_OFFSET));

        short hostIdOff = (short) (paramsOffset + Consts.PACKET_PARAMS_GENERATERANDOM_IN_HOSTID_OFFSET);
        verifySignature(apdubuf, quorumCtx, (short) (hostIdOff + Consts.HOST_ID_SIZE), hostIdOff);

        quorumCtx.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_GenerateRandomData, quorumCtx.FindHost(apdubuf, hostIdOff));

        byte[] encr_buffer = new byte[numOfBytes];
        short len = quorumCtx.GenerateRandom(encr_buffer, (short) 0, numOfBytes);

        len = quorumCtx.EncryptUsingAES(encr_buffer, (short) 0, len, apdubuf, Consts.PACKET_PARAMS_GENERATERANDOM_OUT_DATA_OFFSET);
        Util.setShort(apdubuf, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET, len);

        len += Consts.SHORT_SIZE;
        len += quorumCtx.signApdu(apdubuf, len);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Verifies packet signature
     *
     * @param apdubuf   apdu buffer
     * @param quorumCtx quorum context
     * @param sisgOff   signature offset
     * @param hostIdOff host's ID offset
     */
    void verifySignature(byte[] apdubuf, QuorumContext quorumCtx, short sisgOff, short hostIdOff) {
        short sig_len = Util.getShort(apdubuf, sisgOff);
        //correct the packet size for signature verification
        apdubuf[Consts.PACKET_SIZE_OFFSET] -= (byte) (sig_len + Consts.SHORT_SIZE);
        sisgOff += Consts.SHORT_SIZE;
        quorumCtx.VerifyPacketSignature(apdubuf, hostIdOff, sisgOff, sig_len, (short) 0, (short) (sisgOff - Consts.SHORT_SIZE));
    }

    /**
     * Creates a success outgoing APDU.
     * 2B Nonce length | nonce | 2B signature length | signature
     *
     * @param apdubuf     APDU buffer
     * @param quorumCtx   quorum context
     * @param nonceOffset received nonce offset
     * @return length of the packet
     */
    short createOutgoingSuccessApdu(byte[] apdubuf, QuorumContext quorumCtx, short nonceOffset) {

        byte[] nonce = new byte[Consts.APDU_SIG_NONCE_SIZE];
        Util.arrayCopyNonAtomic(apdubuf, nonceOffset, nonce, (short) 0, Consts.APDU_SIG_NONCE_SIZE);


        short len = quorumCtx.GenerateNonce(apdubuf, Consts.PACKET_PARAMS_SUCCESS_APDU_NONCE_OFFSET, Consts.APDU_SIG_NONCE_SIZE);
        Util.setShort(apdubuf, Consts.PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET, len);
        len += Consts.SHORT_SIZE;

        len += quorumCtx.signApduBufferWNonce(apdubuf, (short) 0, len, nonce, (short) 0, (short) nonce.length,
                apdubuf, len);

        return len;
    }

}
