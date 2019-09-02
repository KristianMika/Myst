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

    //For preloading
    public BigInteger k_Bn_pre;
    public ECPoint Ri_EC_pre;
    public byte[] Ri_Hash_pre;
    
    //Storing pubkeys
    public byte[][] pub_key_hashes;
    public byte[][] pub_keys;
    
    public ECPoint Yagg;

    public SimulatedMPCPlayer(short playerID, ECPoint G, BigInteger n, ECCurve curve) throws NoSuchAlgorithmException {
        this.playerID = playerID;
        this.curve_G = G;
        this.curve_n = n;
        this.curve = curve;

        this.KeyGen();
        SecureRandom random = new SecureRandom();
        secret_seed = new byte[32];
        random.nextBytes(secret_seed);
    }

    //
    // MPCPlayer methods
    //
    @Override
    public byte[] Gen_Rin(short quorumIndex, short i) throws NoSuchAlgorithmException, Exception {
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
    public boolean Setup(short quorumIndex, short numPlayers, short thisPlayerID) throws Exception {
        pub_key_hashes = new byte[MPCGlobals.players.size() - 1][]; 
        pub_keys =  new byte[MPCGlobals.players.size() - 1][];
        return true;
    }

    @Override
    public boolean Reset(short quorumIndex) throws Exception {
        // TODO: at the moment, simulated player performs nothing
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
        if (playerIndex > this.GetPlayerIndex(quorumIndex))
        {
            pub_key_hashes[playerIndex - 1] = hash_arr;
        } else {
            pub_key_hashes[playerIndex] = hash_arr;
        }
        
        return true;
    }

    @Override
    public byte[] RetrievePubKey(short quorumIndex) throws Exception {
        return pub_key_EC.getEncoded(false);
    }

    @Override
    public boolean StorePubKey(short quorumIndex, short playerIndex, byte[] pub_arr) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(pub_arr);
        byte[] hash_comp = md.digest();
        boolean is_valid;
        if (playerIndex > this.GetPlayerIndex(quorumIndex)) {
            is_valid = Arrays.equals(hash_comp, pub_key_hashes[playerIndex - 1]);
            pub_keys[playerIndex - 1] = pub_arr;
        } else {
            is_valid = Arrays.equals(hash_comp, pub_key_hashes[playerIndex]);
            pub_keys[playerIndex] = pub_arr;
        }
        return is_valid;
    }

    @Override
    public boolean RetrieveAggPubKey(short quorumIndex) throws Exception {
        Yagg = curve.getInfinity();
        for (byte[] pubkey : pub_keys){
            Yagg = Yagg.add(Util.ECPointDeSerialization(curve, pubkey, 0)); 
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
}
