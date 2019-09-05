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

    //For preloading
    public BigInteger k_Bn_pre;
    public ECPoint Ri_EC_pre;
    public byte[] Ri_Hash_pre;

    class Player {
        public byte[] pubKey = null;
        public boolean pubKeyValid = false;
        public byte[] pubKeyHash = null;
        public boolean pubKeyHashValid = false;
    }

    private Player[] players;
    
    public ECPoint Yagg;

    public short CARD_INDEX_THIS;
    public static short NUM_PLAYERS;

    //Consts - should be moved somewhere else
    public static final short MAX_NUM_PLAYERS = (short) 15;
    public static final short BASIC_ECC_LENGTH = (short) 32;
    public static final short SECRET_SEED_SIZE = BASIC_ECC_LENGTH;

    public SimulatedMPCPlayer(short playerID, ECPoint G, BigInteger n, ECCurve curve) throws NoSuchAlgorithmException {
        this.playerID = playerID;
        this.curve_G = G;
        this.curve_n = n;
        this.curve = curve;

        this.KeyGen();
        SecureRandom random = new SecureRandom();
        secret_seed = new byte[SECRET_SEED_SIZE];
        random.nextBytes(secret_seed);
    }

    // TODO: Change assertions to conditions + exceptions
    //
    // MPCPlayer methods
    //
    @Override
    public byte[] Gen_Rin(short quorumIndex, short i) throws NoSuchAlgorithmException, Exception {
        assert (i > signature_counter);
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
        assert (numPlayers <= MAX_NUM_PLAYERS && numPlayers >= 1);
        assert (thisPlayerIndex < MAX_NUM_PLAYERS && thisPlayerIndex >= 0);

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

        return true;
    }

    @Override
    public boolean Reset(short quorumIndex) throws Exception {
        Invalidate(true);
        return true;
    }

    @Override
    public BigInteger Sign(short quorumIndex, int round, byte[] Rn, byte[] plaintext) throws Exception {
        Bignat roundBn = Util.makeBignatFromValue(round);
        return Sign(roundBn, Util.ECPointDeSerialization(curve, Rn, 0), plaintext);
    }

    @Override
    public boolean GenKeyPair(short quorumIndex) throws Exception {
        this.KeyGen();
        return true;
    }

    @Override
    public boolean RetrievePubKeyHash(short quorumIndex) throws Exception {
        return true;
    }

    @Override
    public boolean StorePubKeyHash(short quorumIndex, short playerIndex, byte[] hash_arr) throws Exception {
        assert (playerIndex >= 0 && playerIndex != CARD_INDEX_THIS && playerIndex < NUM_PLAYERS);
        //check if commitment is already stored
        assert (!players[playerIndex].pubKeyHashValid);

        players[playerIndex].pubKeyHash = hash_arr;
        players[playerIndex].pubKeyHashValid = true;
        return true;
    }

    @Override
    public byte[] RetrievePubKey(short quorumIndex) throws Exception {
        return pub_key_EC.getEncoded(false);
    }

    @Override
    public boolean StorePubKey(short quorumIndex, short playerIndex, byte[] pub_arr) throws Exception {
        assert (playerIndex >= 0 && playerIndex != CARD_INDEX_THIS && playerIndex < NUM_PLAYERS);
        assert (!players[playerIndex].pubKeyValid);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(pub_arr);
        byte[] hash_comp = md.digest();
        assert (Arrays.equals(hash_comp, players[playerIndex].pubKeyHash));

        players[playerIndex].pubKey = pub_arr;
        players[playerIndex].pubKeyValid = true;
        return true;
    }

    @Override
    public boolean RetrieveAggPubKey(short quorumIndex) throws Exception {
        Yagg = curve.getInfinity();
        for (short i = 0; i < NUM_PLAYERS; i++){
            if (i != CARD_INDEX_THIS){
                assert (players[i].pubKeyValid);
                Yagg = Yagg.add(Util.ECPointDeSerialization(curve, players[i].pubKey, 0));
            }
        }
        Yagg = Yagg.add(pub_key_EC);
        return true;
    }
    
    @Override
    public byte[] Encrypt(short quorumIndex, byte[] plaintext) throws Exception { 
        SecureRandom rnd = new SecureRandom();
        BigInteger rand_r = new BigInteger(256, rnd);
        MPCGlobals.c1 = curve_G.multiply(rand_r);
        MPCGlobals.c2 = MPCGlobals.AggPubKey.multiply(rand_r).add(Util.ECPointDeSerialization(curve, plaintext, 0));
        return Util.joinArray(MPCGlobals.c1.getEncoded(false), MPCGlobals.c2.getEncoded(false));
    }

    @Override
    public byte[] Decrypt(short quorumIndex, byte[] ciphertext) throws Exception {
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
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(pub_key_EC.getEncoded(false));
        pub_key_Hash = md.digest();
    }
                            
    private BigInteger Sign(Bignat i, ECPoint R_EC, byte[] plaintext) throws NoSuchAlgorithmException {
        // TODO: Check if "i" hasn't been used before
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

    private void Invalidate(boolean bEraseAllArrays) {
        SecureRandom random = new SecureRandom();

        if (bEraseAllArrays) {
            random.nextBytes(secret_seed);
            priv_key_BI = new BigInteger(256, random);
            pub_key_EC = curve_G.multiply(priv_key_BI);
            random.nextBytes(pub_key_Hash);
        }

        signature_counter = 0;

        for (Player playerI : players) {
            playerI.pubKeyHashValid = false;
            playerI.pubKeyValid = false;
            if (bEraseAllArrays)
            {
                random.nextBytes(playerI.pubKey);
                random.nextBytes(playerI.pubKeyHash);
            }
        }
    }
}
