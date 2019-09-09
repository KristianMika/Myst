package mpctestclient;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import org.bouncycastle.math.ec.ECCurve;



/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
class SimulatedMPCPlayer implements MPCPlayer {

    public ECPoint G;
    public BigInteger n;
    public ECCurve curve;

    public QuorumContext[] quorums;


    public static final short MAX_QUORUMS = 5;

    public SimulatedMPCPlayer(ECPoint G, BigInteger n, ECCurve curve) throws StateModel.stateException {
        this.G = G;
        this.n = n;
        this.curve = curve;

        // Quorums initialization
        quorums = new QuorumContext[MAX_QUORUMS];
        for (short i = 0; i < quorums.length; i++) {
            quorums[i] = new QuorumContext(G, n, curve);
        }
    }

    @Override
    public boolean Setup(short quorumIndex, short numPlayers, short thisPlayerIndex) throws Exception {
        assert (quorumIndex >= 0 && quorumIndex < MAX_QUORUMS) : "Quorum index is out of accepted interval";
        return quorums[quorumIndex].Setup(numPlayers, thisPlayerIndex);
    }

    //
    // MPCPlayer methods
    //
    @Override
    public byte[] Gen_Rin(short quorumIndex, short i) throws Exception {
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
    public boolean Reset(short quorumIndex) throws Exception {
        quorums[quorumIndex].Reset();
        return true;
    }

    @Override
    public BigInteger Sign(short quorumIndex, int round, byte[] Rn, byte[] plaintext) throws Exception {
        return quorums[quorumIndex].Sign(round, Rn, plaintext);
    }

    @Override
    public boolean GenKeyPair(short quorumIndex) throws Exception {
        quorums[quorumIndex].GenKeyPair();
        return true;
    }

    @Override
    public boolean RetrievePubKeyHash(short quorumIndex) throws Exception {
        return quorums[quorumIndex].RetrievePubKeyHash();
    }

    @Override
    public boolean StorePubKeyHash(short quorumIndex, short playerIndex, byte[] hash_arr) throws Exception {
        return quorums[quorumIndex].StorePubKeyHash(playerIndex, hash_arr);
    }

    @Override
    public byte[] RetrievePubKey(short quorumIndex) throws Exception {
        return quorums[quorumIndex].RetrievePubKey();
    }

    @Override
    public boolean StorePubKey(short quorumIndex, short playerIndex, byte[] pub_arr) throws Exception {
        return quorums[quorumIndex].StorePubKey(playerIndex, pub_arr);
    }

    @Override
    public boolean RetrieveAggPubKey(short quorumIndex) throws Exception {
        return quorums[quorumIndex].RetrieveAggPubKey();
    }
    
    @Override
    public byte[] Encrypt(short quorumIndex, byte[] plaintext) throws Exception {
        return quorums[quorumIndex].Encrypt(plaintext);
    }

    @Override
    public byte[] Decrypt(short quorumIndex, byte[] ciphertext) throws Exception {
        return quorums[quorumIndex].Decrypt(ciphertext);
    }

    @Override
    public void disconnect() {
    }
}
