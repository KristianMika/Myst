package mpctestclient;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.PrivateKey;


/**
 * Implementation of MPCPlayer that simulates a player.
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
class SimulatedMPCPlayer implements MPCPlayer {


    public static final short MAX_QUORUMS = 5;
    public QuorumContext[] quorums;

    public SimulatedMPCPlayer(MPCGlobals mpcGlobals) throws StateModel.StateException {
        // Quorums initialization
        quorums = new QuorumContext[MAX_QUORUMS];
        for (short i = 0; i < quorums.length; i++) {
            quorums[i] = new QuorumContext(mpcGlobals);
        }
    }

    @Override
    public boolean SetHostAuthPubkey(ECPoint pubkey, short aclByte, short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) {
        return true;
    }

    @Override
    public boolean Setup(short quorumIndex, short numPlayers, short thisPlayerIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        if (quorumIndex < 0 || quorumIndex >= MAX_QUORUMS) {
            throw new SimulatedPlayerException("Invalid quorum index.");
        }
        return quorums[quorumIndex].Setup(numPlayers, thisPlayerIndex);
    }

    //
    // MPCPlayer methods
    //
    @Override
    public byte[] Gen_Rin(short quorumIndex, short i, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        return quorums[quorumIndex].Gen_Rin(i);
    }

    @Override
    public ECPoint GetPubKey(short quorumIndex) {
        return quorums[quorumIndex].pub_key_EC;
    }

    @Override
    public short GetPlayerIndex(short quorumIndex) {
        return quorums[quorumIndex].CARD_INDEX_THIS;
    }

    @Override
    public byte[] GetPubKeyHash(short quorumIndex) {
        return quorums[quorumIndex].pub_key_Hash;
    }

    @Override
    public ECPoint GetAggregatedPubKey(short quorumIndex) {
        return quorums[quorumIndex].Yagg;
    }

    @Override
    public BigInteger GetE(short quorumIndex) {
        return quorums[quorumIndex].e_BI;
    }

    @Override
    public boolean Reset(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        quorums[quorumIndex].Reset();
        return true;
    }

    @Override
    public boolean Remove(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws SimulatedPlayerException, StateModel.StateException {
        if (quorumIndex < 0 || quorumIndex >= MAX_QUORUMS) {
            throw new SimulatedPlayerException("Invalid quorum index.");
        }
        quorums[quorumIndex].Reset();
        return true;
    }

    @Override
    public BigInteger Sign(short quorumIndex, int round, byte[] Rn, byte[] plaintext, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        return quorums[quorumIndex].Sign(round, Rn, plaintext);
    }

    @Override
    public boolean GenKeyPair(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        quorums[quorumIndex].GenKeyPair();
        return true;
    }

    @Override
    public boolean RetrievePubKeyHash(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        return quorums[quorumIndex].RetrievePubKeyHash();
    }

    @Override
    public boolean StorePubKeyHash(short quorumIndex, short playerIndex, byte[] hash_arr, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        return quorums[quorumIndex].StorePubKeyHash(playerIndex, hash_arr);
    }

    @Override
    public byte[] RetrievePubKey(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey, MPCGlobals mpcGlobals) throws Exception {
        return quorums[quorumIndex].RetrievePubKey();
    }

    @Override
    public boolean StorePubKey(short quorumIndex, short playerIndex, byte[] pub_arr, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        return quorums[quorumIndex].StorePubKey(playerIndex, pub_arr);
    }

    @Override
    public boolean RetrieveAggPubKey(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        return quorums[quorumIndex].RetrieveAggPubKey();
    }

    @Override
    public byte[] Encrypt(short quorumIndex, byte[] plaintext, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        return quorums[quorumIndex].Encrypt(plaintext);
    }

    @Override
    public byte[] Decrypt(short quorumIndex, byte[] ciphertext, byte hostIndex, PrivateKey hostPrivKey) throws Exception {
        return quorums[quorumIndex].Decrypt(ciphertext);
    }

    @Override
    public byte[] GenerateRandom(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey, short numOfBytes) throws Exception {
        return quorums[quorumIndex].GenerateRandom(numOfBytes);
    }

    @Override
    public void disconnect() {
    }

    static class SimulatedPlayerException extends Exception {
        SimulatedPlayerException(String errorMessage) {
            super(errorMessage);
        }
    }
}
