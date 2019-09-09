package mpctestclient;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECPoint;

import ds.ov2.bignat.Bignat;
import org.bouncycastle.math.ec.ECCurve;



/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
class SimulatedMPCPlayer implements MPCPlayer {

    public short playerID;

    ECCurve curve;
    //Key Pair
    public BigInteger priv_key_BI;
    public ECPoint pub_key_EC;
    public byte[] pub_key_Hash;
    public ECPoint curve_G;
    public BigInteger curve_n;
    //Signing
    public byte[] secret_seed;//{ (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    public BigInteger k_Bn;
    public ECPoint Ri_EC;
    public byte[] Ri_Hash;
    public BigInteger e_BI;
    public short signature_counter;
    public Bignat signature_counter_Bn;

    //For preloading
    public BigInteger k_Bn_pre;
    public ECPoint Ri_EC_pre;
    public byte[] Ri_Hash_pre;

    public short num_commitments_count;
    public short num_pubkeys_count;

    class Player {
        public byte[] pubKey = null;
        public boolean pubKeyValid = false;
        public byte[] pubKeyHash = null;
        public boolean pubKeyHashValid = false;
    }

    private Player[] players;
    private StateModel state = null;
    
    public ECPoint Yagg;
    public short Yagg_shares_count;

    public short CARD_INDEX_THIS;
    public static short NUM_PLAYERS;

    //Consts - should be moved somewhere else
    public static final short MAX_NUM_PLAYERS = (short) 15;
    public static final short BASIC_ECC_LENGTH = (short) 32;
    public static final short SECRET_SEED_SIZE = BASIC_ECC_LENGTH;

    public SimulatedMPCPlayer(short playerID, ECPoint G, BigInteger n, ECCurve curve) throws NoSuchAlgorithmException, StateModel.stateException {
        this.playerID = playerID;
        this.curve_G = G;
        this.curve_n = n;
        this.curve = curve;

        Yagg = curve.getInfinity(); // TODO: Initialise Yagg somwhere else
        this.KeyGen(); // TODO: Remove Keygen
        SecureRandom random = new SecureRandom();
        secret_seed = new byte[SECRET_SEED_SIZE];
        random.nextBytes(secret_seed);
        signature_counter_Bn = new Bignat((short) 2);


        state = new StateModel();
        state.MakeStateTransition(StateModel.STATE_QUORUM_CLEARED);
    }

    //
    // MPCPlayer methods
    //
    @Override
    public byte[] Gen_Rin(short quorumIndex, short i) throws NoSuchAlgorithmException, Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Sign_RetrieveRandomRi);
        assert (i > signature_counter) : "Signature counter " + i + " has already been used";
        signature_counter = i;

        Bignat counter = Util.makeBignatFromValue((int) i);
        ECPoint Rin = curve_G.multiply(new BigInteger(PRF(counter, this.secret_seed)));
        return Rin.getEncoded(false);
    }

    @Override
    public ECPoint GetPubKey(short quorumIndex) {
        return pub_key_EC;
    }

    @Override
    public short GetPlayerIndex(short quorumIndex) {
        return playerID;
    }

    @Override
    public byte[] GetPubKeyHash(short quorumIndex) {
        return pub_key_Hash;
    }

    @Override
    public ECPoint GetAggregatedPubKey(short quorumIndex) {
        return Yagg;
    }

    @Override
    public BigInteger GetE(short quorumIndex) {
        return e_BI;
    }

    @Override
    public boolean Setup(short quorumIndex, short numPlayers, short thisPlayerIndex) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_SetupNew);
        assert (numPlayers <= MAX_NUM_PLAYERS && numPlayers >= 1) : "Number of players is out of accepted interval";
        assert (thisPlayerIndex < MAX_NUM_PLAYERS && thisPlayerIndex >= 0) : "Player's index is out of accepted interval";

        players = new Player[numPlayers];
        for (short i = 0; i < numPlayers;i++) {
            players[i] = new Player();

            players[i].pubKey = new byte[BASIC_ECC_LENGTH];
            players[i].pubKeyHash = new byte[BASIC_ECC_LENGTH];
        }

        // simulated player can currently participate in only one quorum
        Reset((short) 0);

        CARD_INDEX_THIS = thisPlayerIndex;
        NUM_PLAYERS = numPlayers;

        state.MakeStateTransition(StateModel.STATE_QUORUM_INITIALIZED);
        state.MakeStateTransition(StateModel.STATE_KEYGEN_CLEARED);
        return true;
    }

    @Override
    public boolean Reset(short quorumIndex) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Reset);
        Invalidate(true);
        state.MakeStateTransition(StateModel.STATE_QUORUM_CLEARED);
        return true;
    }

    @Override
    public BigInteger Sign(short quorumIndex, int round, byte[] Rn, byte[] plaintext) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Sign);
        Bignat roundBn = Util.makeBignatFromValue(round);
        return Sign(roundBn, Util.ECPointDeSerialization(curve, Rn, 0), plaintext);
    }

    @Override
    public boolean GenKeyPair(short quorumIndex) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_InitAndGenerateKeyPair);

        Invalidate(false);

        state.MakeStateTransition(StateModel.STATE_QUORUM_INITIALIZED);
        state.MakeStateTransition(StateModel.STATE_KEYGEN_CLEARED);

        this.KeyGen();
        state.MakeStateTransition(StateModel.STATE_KEYGEN_PRIVATEGENERATED);

        return true;
    }

    @Override
    public boolean RetrievePubKeyHash(short quorumIndex) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_RetrieveCommitment);

        // In extreme case, when quorum is of size 1 and StoreCommitment() is skipped, the state transition has to happen here
        if (NUM_PLAYERS == 1) {
            state.MakeStateTransition(StateModel.STATE_KEYGEN_COMMITMENTSCOLLECTED);
        }

        return true;
    }

    @Override
    public boolean StorePubKeyHash(short quorumIndex, short playerIndex, byte[] hash_arr) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_StoreCommitment);

        assert (playerIndex >= 0 && playerIndex != CARD_INDEX_THIS && playerIndex < NUM_PLAYERS) : "Player's index is out of accepted interval";
        assert (!players[playerIndex].pubKeyHashValid) : "Player's commitment has already been stored";

        players[playerIndex].pubKeyHash = hash_arr;
        players[playerIndex].pubKeyHashValid = true;
        num_commitments_count++;

        if (num_commitments_count == NUM_PLAYERS) {
            state.MakeStateTransition(StateModel.STATE_KEYGEN_COMMITMENTSCOLLECTED);
        }
        return true;
    }

    @Override
    public byte[] RetrievePubKey(short quorumIndex) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GetYi);

        // In extreme case, when quorum is of size 1 and SetYs() is skipped, the state transition has to happen here
        if (NUM_PLAYERS == 1) {
            state.MakeStateTransition(StateModel.STATE_KEYGEN_SHARESCOLLECTED);
            state.MakeStateTransition(StateModel.STATE_KEYGEN_KEYPAIRGENERATED);
        }

        return pub_key_EC.getEncoded(false);
    }

    @Override
    public boolean StorePubKey(short quorumIndex, short playerIndex, byte[] pub_arr) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_SetYs);
        assert (playerIndex >= 0 && playerIndex != CARD_INDEX_THIS && playerIndex < NUM_PLAYERS) : "Player's index is out of accepted interval";
        assert (!players[playerIndex].pubKeyValid) : "Player's public key has already been stored";;

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(pub_arr);
        byte[] hash_comp = md.digest();
        assert (Arrays.equals(hash_comp, players[playerIndex].pubKeyHash)) : "Pubkey to be stored does not match stored hash";

        players[playerIndex].pubKey = pub_arr;
        players[playerIndex].pubKeyValid = true;
        num_pubkeys_count++;
        Yagg = Yagg.add(Util.ECPointDeSerialization(curve, pub_arr, 0));
        Yagg_shares_count++;
        if (num_pubkeys_count == NUM_PLAYERS){
            state.MakeStateTransition(StateModel.STATE_KEYGEN_SHARESCOLLECTED);
            if (Yagg_shares_count == NUM_PLAYERS){
                state.MakeStateTransition(StateModel.STATE_KEYGEN_KEYPAIRGENERATED);
            }
        }
        return true;
    }

    @Override
    public boolean RetrieveAggPubKey(short quorumIndex) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GetY);
        return true;
    }
    
    @Override
    public byte[] Encrypt(short quorumIndex, byte[] plaintext) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Encrypt);

        SecureRandom rnd = new SecureRandom();
        BigInteger rand_r = new BigInteger(256, rnd);
        MPCGlobals.c1 = curve_G.multiply(rand_r);
        MPCGlobals.c2 = MPCGlobals.AggPubKey.multiply(rand_r).add(Util.ECPointDeSerialization(curve, plaintext, 0));
        return Util.joinArray(MPCGlobals.c1.getEncoded(false), MPCGlobals.c2.getEncoded(false));
    }

    @Override
    public byte[] Decrypt(short quorumIndex, byte[] ciphertext) throws Exception {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_DecryptShare);

        ECPoint c1 = Util.ECPointDeSerialization(curve, ciphertext, 0);
        ECPoint xc1_share = c1.multiply(priv_key_BI);
        return xc1_share.getEncoded(false);
    }

    @Override
    public void disconnect() {
    }

    //
    // SimulatedMPCPlayer helper methods
    //
    private final void SetPrivKey(BigInteger privkey) {
        priv_key_BI = privkey;
        pub_key_EC = curve_G.multiply(priv_key_BI);
    }

    private final void KeyGen() throws NoSuchAlgorithmException {
        // Keypair + hash
        SecureRandom rnd = new SecureRandom();
        priv_key_BI = new BigInteger(256, rnd);
        if (MPCTestClient._FIXED_PLAYERS_RNG) {
            System.out.println("WARNING: _FIXED_PLAYERS_RNG == true");
            // If true, don't generate random key, but use fixed one instead
            priv_key_BI = new BigInteger("B346675518084623BC111CC53FF615B152A3F6D1585278370FA1BA0EA160237E".getBytes());
        }
        
        pub_key_EC = curve_G.multiply(priv_key_BI);
        num_pubkeys_count++;

        Yagg = Yagg.add(pub_key_EC);
        Yagg_shares_count++;

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(pub_key_EC.getEncoded(false));
        pub_key_Hash = md.digest();
        num_commitments_count++;
    }
                            
    private BigInteger Sign(Bignat i, ECPoint R_EC, byte[] plaintext) throws NoSuchAlgorithmException {
        assert (signature_counter_Bn.lesser(i)) : "Signature counter has already been used.";
        signature_counter_Bn.copy(i);
        //Gen e (e will be the same in all signature shares)
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        
        //System.out.println("Simulated: Plaintext:" + Util.bytesToHex(plaintext));
        //System.out.println("Simulated: Ri,n:     " + Util.bytesToHex(R_EC.getEncoded(false)));
        md.update(plaintext);
        md.update(R_EC.getEncoded(false)); // R_EC is the sum of the r_i's
        byte[] e = md.digest();
        e_BI = new BigInteger(1, e);
        
        //Gen s_i
        
        this.k_Bn = new BigInteger(PRF(i, secret_seed));
        BigInteger s_i_BI = this.k_Bn.subtract(e_BI.multiply(this.priv_key_BI));
        s_i_BI = s_i_BI.mod(curve_n);

        /* BUGBUG: I'm cheating a bit here, and use the e returned by the JC.
         Btw e is always the same, so it can actually be computed 
         on the host if this helps with optimizing the applet */
        //System.out.println("Simulated: s:        " + Util.bytesToHex(s_i_BI.toByteArray()));
        //System.out.println("Simulated: e:        " + Util.bytesToHex(e) + "\n");
        return s_i_BI;
    }

    private byte[] PRF(Bignat i, byte[] seed) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.reset();
        md.update(i.as_byte_array());
        md.update(seed);
        return md.digest();
    }

    private void Invalidate(boolean bEraseAllArrays) throws StateModel.stateException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Invalidate);

        SecureRandom random = new SecureRandom();

        if (bEraseAllArrays) {
            random.nextBytes(secret_seed);
            priv_key_BI = new BigInteger(256, random);
            pub_key_EC = curve_G.multiply(priv_key_BI);
            random.nextBytes(pub_key_Hash);
            num_commitments_count = 0;
            num_pubkeys_count = 0;
        }
        Yagg = curve.getInfinity();
        Yagg_shares_count = 0;
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
}
