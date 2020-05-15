package mpctestclient;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.ArrayList;


/**
 * Implementation of MPCPlayer that simulates a player.
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
class SimulatedMPCPlayer implements MPCPlayer {


    public static final short MAX_QUORUMS = 5;
    public ArrayList<QuorumContext> quorums;

    public SimulatedMPCPlayer(MPCGlobals mpcGlobals) throws MPCException {
        // Quorums initialization
        quorums = new ArrayList<>();
        for (short i = 0; i < MAX_QUORUMS; i++) {
            quorums.add(new QuorumContext(mpcGlobals));
        }
    }

    @Override
    public boolean SetHostAuthPubkey(ECPoint pubkey, short aclByte, short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws MPCException {
        QuorumContext currContext = quorums.get(quorumIndex);
        if (currContext.hostInitialised) {
            currContext.VerifyCallerAuthorization(mpc.StateModel.FNC_INS_PERSONALIZE_SET_USER_AUTH_PUBKEY, hostId);
        }
        quorums.get(quorumIndex).SetHostAuthPubkey(pubkey, aclByte, hostId);
        return true;
    }

    @Override
    public boolean Setup(short quorumIndex, short numPlayers, short thisPlayerIndex, byte[] hostId, PrivateKey hostPrivKey) throws MPCException {
        if (quorumIndex < 0 || quorumIndex >= MAX_QUORUMS) {
            throw new MPCException("Invalid quorum index.");
        }

        QuorumContext currContext = quorums.get(quorumIndex);
        if (currContext.hostInitialised) {
            currContext.VerifyCallerAuthorization(mpc.StateModel.FNC_QuorumContext_SetupNew, hostId);
        }
        return currContext.Setup(numPlayers, thisPlayerIndex, hostId);
    }

    //
    // MPCPlayer methods
    //
    @Override
    public byte[] Gen_Rin(short quorumIndex, short i, byte[] hostId, PrivateKey hostPrivKey) throws MPCException, NoSuchAlgorithmException {
        quorums.get(quorumIndex).VerifyCallerAuthorization(StateModel.FNC_QuorumContext_Sign_RetrieveRandomRi, hostId);
        return quorums.get(quorumIndex).Gen_Rin(i, hostId);
    }

    @Override
    public ECPoint GetPubKey(short quorumIndex) {
        return quorums.get(quorumIndex).pub_key_EC;
    }

    @Override
    public short GetPlayerIndex(short quorumIndex) {
        return quorums.get(quorumIndex).CARD_INDEX_THIS;
    }

    @Override
    public byte[] GetPubKeyHash(short quorumIndex) {
        return quorums.get(quorumIndex).pub_key_Hash;
    }

    @Override
    public ECPoint GetAggregatedPubKey(short quorumIndex) {
        return quorums.get(quorumIndex).Yagg;
    }

    @Override
    public BigInteger GetE(short quorumIndex) {
        return quorums.get(quorumIndex).e_BI;
    }

    @Override
    public boolean Reset(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception {
        QuorumContext currContext = quorums.get(quorumIndex);
        if (currContext.hostInitialised) {
            currContext.VerifyCallerAuthorization(StateModel.FNC_QuorumContext_Reset, hostId);
        }
        currContext.Reset();
        return true;
    }

    @Override
    public boolean Remove(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws MPCException {
        if (quorumIndex < 0 || quorumIndex >= MAX_QUORUMS) {
            throw new MPCException("Invalid quorum index.");
        }
        quorums.get(quorumIndex).Reset();
        return true;
    }

    @Override
    public BigInteger Sign(short quorumIndex, int round, byte[] Rn, byte[] plaintext, byte[] hostId, PrivateKey hostPrivKey) throws MPCException, NoSuchAlgorithmException {
        quorums.get(quorumIndex).VerifyCallerAuthorization(StateModel.FNC_QuorumContext_Sign, hostId);
        return quorums.get(quorumIndex).Sign(round, Rn, plaintext);
    }

    @Override
    public boolean GenKeyPair(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws MPCException, NoSuchAlgorithmException {
        quorums.get(quorumIndex).VerifyCallerAuthorization(StateModel.FNC_QuorumContext_InitAndGenerateKeyPair, hostId);
        quorums.get(quorumIndex).GenKeyPair();
        return true;
    }

    @Override
    public boolean RetrievePubKeyHash(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws MPCException {
        quorums.get(quorumIndex).VerifyCallerAuthorization(StateModel.FNC_QuorumContext_RetrieveCommitment, hostId);
        return quorums.get(quorumIndex).RetrievePubKeyHash();
    }

    @Override
    public boolean StorePubKeyHash(short quorumIndex, short playerIndex, byte[] hash_arr, byte[] hostId, PrivateKey hostPrivKey) throws MPCException {
        quorums.get(quorumIndex).VerifyCallerAuthorization(StateModel.FNC_QuorumContext_StoreCommitment, hostId);
        return quorums.get(quorumIndex).StorePubKeyHash(playerIndex, hash_arr);
    }

    @Override
    public byte[] RetrievePubKey(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey, MPCGlobals mpcGlobals) throws MPCException {
        quorums.get(quorumIndex).VerifyCallerAuthorization(StateModel.FNC_QuorumContext_GetYi, hostId);
        return quorums.get(quorumIndex).RetrievePubKey();
    }

    @Override
    public boolean StorePubKey(short quorumIndex, short playerIndex, byte[] pub_arr, byte[] hostId, PrivateKey hostPrivKey) throws MPCException, NoSuchAlgorithmException {
        quorums.get(quorumIndex).VerifyCallerAuthorization(StateModel.FNC_QuorumContext_SetYs, hostId);
        return quorums.get(quorumIndex).StorePubKey(playerIndex, pub_arr);
    }

    @Override
    public boolean RetrieveAggPubKey(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws MPCException {
        quorums.get(quorumIndex).VerifyCallerAuthorization(StateModel.FNC_QuorumContext_GetY, hostId);
        return quorums.get(quorumIndex).RetrieveAggPubKey();
    }

    @Override
    public byte[] Encrypt(short quorumIndex, byte[] plaintext, byte[] hostId, PrivateKey hostPrivKey) throws MPCException {
        quorums.get(quorumIndex).VerifyCallerAuthorization(StateModel.FNC_QuorumContext_Encrypt, hostId);
        return quorums.get(quorumIndex).Encrypt(plaintext);
    }

    @Override
    public byte[] Decrypt(short quorumIndex, byte[] ciphertext, byte[] hostId, PrivateKey hostPrivKey) throws MPCException {
        quorums.get(quorumIndex).VerifyCallerAuthorization(StateModel.FNC_QuorumContext_DecryptShare, hostId);
        return quorums.get(quorumIndex).Decrypt(ciphertext);
    }

    @Override
    public byte[] GenerateRandom(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey, short numOfBytes) throws MPCException {
        quorums.get(quorumIndex).VerifyCallerAuthorization(StateModel.FNC_QuorumContext_GenerateRandomData, hostId);
        return quorums.get(quorumIndex).GenerateRandom(numOfBytes);
    }

    @Override
    public void disconnect() {
    }

}
