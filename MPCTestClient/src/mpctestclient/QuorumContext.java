package mpctestclient;

import ds.ov2.bignat.Bignat;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import mpc.Consts;



public class QuorumContext {

    ECCurve curve;
    //Key Pair
    public BigInteger priv_key_BI;
    public ECPoint pub_key_EC;
    public byte[] pub_key_Hash;
    public ECPoint curve_G;
    public BigInteger curve_n;

    //Signing
    public byte[] secret_seed;
    public BigInteger k_Bn;
    public BigInteger e_BI;

    public short signature_counter;
    public Bignat signature_counter_Bn;

    public short num_commitments_count;
    public short num_pubkeys_count;

    class Player {
        public byte[] pubKey = null;
        public boolean pubKeyValid = false;
        public byte[] pubKeyHash = null;
        public boolean pubKeyHashValid = false;
    }

    private Player[] players;
    private StateModel state;

    public ECPoint Yagg;
    public short Yagg_shares_count;

    public short CARD_INDEX_THIS;
    public static short NUM_PLAYERS;

    // Consts
    public static final short MAX_NUM_PLAYERS = (short) 15;
    public static final short BASIC_ECC_LENGTH = (short) 32;
    public static final short SECRET_SEED_SIZE = BASIC_ECC_LENGTH;


    public QuorumContext(ECPoint G, BigInteger n, ECCurve curve) throws StateModel.stateException {
        this.curve_G = G;
        this.curve_n = n;
        this.curve = curve;

        // Yagg initialization and secret seed generation
        Yagg = curve.getInfinity();
        SecureRandom random = new SecureRandom();
        secret_seed = new byte[SECRET_SEED_SIZE];
        random.nextBytes(secret_seed);
        signature_counter_Bn = new Bignat((short) 2);

        players = new Player[MAX_NUM_PLAYERS];
        for (short i = 0; i < MAX_NUM_PLAYERS; i++) {
            players[i] = new Player();

            players[i].pubKey = new byte[BASIC_ECC_LENGTH];
            players[i].pubKeyHash = new byte[BASIC_ECC_LENGTH];
        }

        state = new StateModel();
        state.MakeStateTransition(StateModel.STATE_QUORUM_CLEARED);

    }

    public boolean Setup(short numPlayers, short thisPlayerIndex) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_SetupNew);

        Reset();

        if (numPlayers > MAX_NUM_PLAYERS || numPlayers < 1) {
            throw new quorumContextException(Consts.SW_TOOMANYPLAYERS);
        }

        if (thisPlayerIndex >= MAX_NUM_PLAYERS || thisPlayerIndex < 0){
            throw new quorumContextException(Consts.SW_INVALIDPLAYERINDEX);
        }

        NUM_PLAYERS = numPlayers;
        CARD_INDEX_THIS = thisPlayerIndex;

        state.MakeStateTransition(StateModel.STATE_QUORUM_INITIALIZED);
        state.MakeStateTransition(StateModel.STATE_KEYGEN_CLEARED);

        return true;
    }

    public void Reset() throws StateModel.stateException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Reset);
        Invalidate(true);
        state.MakeStateTransition(StateModel.STATE_QUORUM_CLEARED);
    }

    public void GenKeyPair() throws StateModel.stateException, NoSuchAlgorithmException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_InitAndGenerateKeyPair);

        Invalidate(false);

        state.MakeStateTransition(StateModel.STATE_QUORUM_INITIALIZED);
        state.MakeStateTransition(StateModel.STATE_KEYGEN_CLEARED);

        this.KeyGen();
        state.MakeStateTransition(StateModel.STATE_KEYGEN_PRIVATEGENERATED);
    }

    private final void KeyGen() throws NoSuchAlgorithmException {
        SecureRandom rnd = new SecureRandom();
        priv_key_BI = new BigInteger(256, rnd);
        if (MPCTestClient._FIXED_PLAYERS_RNG) {
            System.out.println("WARNING: _FIXED_PLAYERS_RNG == true");
            // If true, don't generate random key, but use fixed one instead
            priv_key_BI = new BigInteger("B346675518084623BC111CC53FF615B152A3F6D1585278370FA1BA0EA160237E".getBytes());
        }

        pub_key_EC = curve_G.multiply(priv_key_BI);
        players[CARD_INDEX_THIS].pubKeyValid = true;
        num_pubkeys_count++;

        // Add recently generated private key to Yagg
        Yagg = Yagg.add(pub_key_EC);
        Yagg_shares_count++;

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(pub_key_EC.getEncoded(false));
        pub_key_Hash = md.digest();
        num_commitments_count++;
    }

    public byte[] Gen_Rin(short i) throws StateModel.stateException, NoSuchAlgorithmException, quorumContextException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Sign_RetrieveRandomRi);
        if (i <= signature_counter) {
            throw new quorumContextException(Consts.SW_INVALIDCOUNTER);
        }
        signature_counter = i;

        Bignat counter = Util.makeBignatFromValue((int) i);
        ECPoint Rin = curve_G.multiply(new BigInteger(PRF(counter, this.secret_seed)));
        return Rin.getEncoded(false);
    }

    public boolean RetrievePubKeyHash() throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_RetrieveCommitment);

        // In extreme case, when quorum is of size 1 and StorePubKeyHash() is skipped, the state transition has to happen here
        if (NUM_PLAYERS == 1) {
            state.MakeStateTransition(StateModel.STATE_KEYGEN_COMMITMENTSCOLLECTED);
        }

        return true;
    }

    public boolean StorePubKeyHash(short playerIndex, byte[] hash_arr) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_StoreCommitment);

        if (playerIndex < 0 || playerIndex == CARD_INDEX_THIS || playerIndex >= NUM_PLAYERS) {
            throw new quorumContextException(Consts.SW_INVALIDPLAYERINDEX);
        }

        if (players[playerIndex].pubKeyHashValid) {
            throw new quorumContextException(Consts.SW_COMMITMENTALREADYSTORED);
        }

        players[playerIndex].pubKeyHash = hash_arr;
        players[playerIndex].pubKeyHashValid = true;
        num_commitments_count++;

        if (num_commitments_count == NUM_PLAYERS) {
            state.MakeStateTransition(StateModel.STATE_KEYGEN_COMMITMENTSCOLLECTED);
        }
        return true;
    }


    public byte[] RetrievePubKey() throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GetYi);

        if (!players[CARD_INDEX_THIS].pubKeyValid) {
            throw new quorumContextException(Consts.SW_INVALIDYSHARE);
        }

        // In extreme case, when quorum is of size 1 and StorePubKey() is skipped, the state transition has to happen here
        if (NUM_PLAYERS == 1) {
            state.MakeStateTransition(StateModel.STATE_KEYGEN_SHARESCOLLECTED);
            state.MakeStateTransition(StateModel.STATE_KEYGEN_KEYPAIRGENERATED);
        }

        return pub_key_EC.getEncoded(false);
    }


    public boolean StorePubKey(short playerIndex, byte[] pub_arr) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_SetYs);

        if (playerIndex < 0 || playerIndex == CARD_INDEX_THIS || playerIndex >= NUM_PLAYERS) {
            throw new quorumContextException(Consts.SW_INVALIDPLAYERINDEX);
        }

        if (players[playerIndex].pubKeyValid) {
            throw new quorumContextException(Consts.SW_SHAREALREADYSTORED);
        }

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(pub_arr);
        byte[] hash_comp = md.digest();

        if (!Arrays.equals(hash_comp, players[playerIndex].pubKeyHash)) {
            throw new quorumContextException(Consts.SW_INVALIDCOMMITMENT);
        }

        players[playerIndex].pubKey = pub_arr;
        players[playerIndex].pubKeyValid = true;
        num_pubkeys_count++;
        Yagg = Yagg.add(Util.ECPointDeSerialization(curve, pub_arr, 0));
        Yagg_shares_count++;
        if (num_pubkeys_count == NUM_PLAYERS) {
            state.MakeStateTransition(StateModel.STATE_KEYGEN_SHARESCOLLECTED);
            if (Yagg_shares_count == NUM_PLAYERS) {
                state.MakeStateTransition(StateModel.STATE_KEYGEN_KEYPAIRGENERATED);
            }
        }
        return true;
    }

    public boolean RetrieveAggPubKey() throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GetY);
        return true;
    }

    //
    // Crypto ops
    //

    public BigInteger Sign(int round, byte[] Rn, byte[] plaintext) throws NoSuchAlgorithmException, StateModel.stateException, quorumContextException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Sign);
        Bignat roundBn = Util.makeBignatFromValue(round);
        ECPoint R_EC = Util.ECPointDeSerialization(curve, Rn, 0);

        if (!signature_counter_Bn.lesser(roundBn)) {
            throw new quorumContextException(Consts.SW_INVALIDCOUNTER);
        }
        signature_counter_Bn.copy(roundBn);
        //Gen e (e will be the same in all signature shares)
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        //System.out.println("Simulated: Plaintext:" + Util.bytesToHex(plaintext));
        //System.out.println("Simulated: Ri,n:     " + Util.bytesToHex(R_EC.getEncoded(false)));
        md.update(plaintext);
        md.update(R_EC.getEncoded(false)); // R_EC is the sum of the r_i's
        byte[] e = md.digest();
        e_BI = new BigInteger(1, e);

        //Gen s_i

        this.k_Bn = new BigInteger(PRF(roundBn, secret_seed));
        BigInteger s_i_BI = this.k_Bn.subtract(e_BI.multiply(this.priv_key_BI));
        s_i_BI = s_i_BI.mod(curve_n);

        //System.out.println("Simulated: s:        " + Util.bytesToHex(s_i_BI.toByteArray()));
        //System.out.println("Simulated: e:        " + Util.bytesToHex(e) + "\n");
        return s_i_BI;
    }

    public byte[] Encrypt(byte[] plaintext) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Encrypt);

        SecureRandom rnd = new SecureRandom();
        BigInteger rand_r = new BigInteger(256, rnd);
        MPCGlobals.c1 = curve_G.multiply(rand_r);
        MPCGlobals.c2 = MPCGlobals.AggPubKey.multiply(rand_r).add(Util.ECPointDeSerialization(curve, plaintext, 0));
        return Util.joinArray(MPCGlobals.c1.getEncoded(false), MPCGlobals.c2.getEncoded(false));
    }

    public byte[] Decrypt(byte[] ciphertext) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_DecryptShare);

        ECPoint c1 = Util.ECPointDeSerialization(curve, ciphertext, 0);
        ECPoint xc1_share = c1.multiply(priv_key_BI);
        return xc1_share.getEncoded(false);
    }

    //
    // Util
    //

    private void Invalidate(boolean bEraseAllArrays) throws StateModel.stateException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Invalidate);

        SecureRandom random = new SecureRandom();

        if (bEraseAllArrays) {
            random.nextBytes(secret_seed);
            priv_key_BI = new BigInteger(256, random);
            pub_key_EC = curve_G.multiply(priv_key_BI);
            num_commitments_count = 0;
            num_pubkeys_count = 0;
            Yagg = curve.getInfinity();
            Yagg_shares_count = 0;
        }

        signature_counter = 0;
        signature_counter_Bn.zero();

        for (Player playerI : players) {
            playerI.pubKeyHashValid = false;
            playerI.pubKeyValid = false;
            if (bEraseAllArrays)
            {
                random.nextBytes(playerI.pubKey);
                random.nextBytes(playerI.pubKeyHash);
            }
        }
        state.MakeStateTransition(StateModel.STATE_QUORUM_CLEARED);
    }

    private byte[] PRF(Bignat i, byte[] seed) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.reset();
        md.update(i.as_byte_array());
        md.update(seed);
        return md.digest();
    }

    // Error handling
    static class quorumContextException extends Exception {
        quorumContextException(short error) {
            super(getErrorMessage(error));
        }
    }
    
    static String getErrorMessage(short error) {
        String message = "";
        switch (error){
            case Consts.SW_TOOMANYPLAYERS:
                message = "Number of players is outside the accepted interval.";
                break;
            case Consts.SW_INVALIDCOMMITMENT :
                message = "Commitment is not valid.";
                break;
            case Consts.SW_INVALIDYSHARE:
                message = "Share is not valid.";
                break;
            case Consts.SW_SHAREALREADYSTORED:
                message = "Share is already stored.";
                break;
            case Consts.SW_INVALIDPLAYERINDEX:
                message = "Player's index is not valid.";
                break;
            case Consts.SW_COMMITMENTALREADYSTORED:
                message = "Commitment is already stored.";
                break;
            case Consts.SW_INVALIDCOUNTER:
                message = "Provided counter is not valid.";
                break;
            case Consts.SW_INVALIDQUORUMINDEX:
                message = "Invalid quorum index.";
                break;
            default:
                message = "Unknown error";
        }
        return message;
    }
}
