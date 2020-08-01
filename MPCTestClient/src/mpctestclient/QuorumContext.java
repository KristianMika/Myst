package mpctestclient;

import ds.ov2.bignat.Bignat;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;


public class QuorumContext {

    // Consts
    public static final short MAX_NUM_PLAYERS = (short) 15;
    public static final short BASIC_ECC_LENGTH = (short) 32;
    public static final short MAX_NUM_HOSTS = (short) 5;
    public static final short SECRET_SEED_SIZE = BASIC_ECC_LENGTH;
    public static final short HOST_ID_SIZE = 4;
    public static short NUM_PLAYERS;
    private final MPCGlobals mpcGlobals;
    private final Player[] players;
    private final StateModel state;
    private final HashMap<ByteWrapper, HostACL> hosts;
    public boolean hostInitialised;
    //Key Pair
    public BigInteger priv_key_BI;
    public ECPoint pub_key_EC;
    public byte[] pub_key_Hash;
    public BigInteger curve_n;
    //Signing
    public byte[] secret_seed;
    public BigInteger k_Bn;
    public BigInteger e_BI;
    public short signature_counter;
    public Bignat signature_counter_Bn;
    public short num_commitments_count;
    public short num_pubkeys_count;
    public ECPoint Yagg;
    public short Yagg_shares_count;
    public short CARD_INDEX_THIS;


    public QuorumContext(MPCGlobals mpcGlobals) throws MPCException {
        this.mpcGlobals = mpcGlobals;

        // Yagg initialization and secret seed generation
        Yagg = mpcGlobals.curve.getInfinity();
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
        hosts = new HashMap<>();
    }

    void SetHostAuthPubkey(ECPoint pubkey, short aclByte, byte[] hostId) throws MPCException {
        if (hosts.size() >= MAX_NUM_HOSTS) {
            throw new MPCException("Too many hosts");
        }

        byte[] newHostId = Arrays.copyOfRange(pubkey.getEncoded(false), 0, HOST_ID_SIZE);

        if (hosts.containsKey(new ByteWrapper(newHostId))) {
            throw new DuplicateHostIdException();
        }

        hosts.put(new ByteWrapper(newHostId), new HostACL(newHostId, aclByte));
        hostInitialised = true;
        state.MakeStateTransition(StateModel.STATE_USER_PUBKEYS_SET);
    }

    /**
     * Setups this Simulated player
     *
     * @param numPlayers      Number of players that will participate in this quorum
     * @param thisPlayerIndex Index of this player
     * @return
     * @throws MPCException
     */
    public boolean Setup(short numPlayers, short thisPlayerIndex, byte[] hostId) throws MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_SetupNew);

        Reset();

        // approves the number of players
        if (numPlayers > MAX_NUM_PLAYERS || numPlayers < 1) {
            throw new MPCException("Number of players is outside the accepted interval.");
        }

        if (thisPlayerIndex >= MAX_NUM_PLAYERS || thisPlayerIndex < 0) {
            throw new MPCException("Player's index is not valid.");
        }

        NUM_PLAYERS = numPlayers;
        CARD_INDEX_THIS = thisPlayerIndex;

        state.MakeStateTransition(StateModel.STATE_QUORUM_INITIALIZED);

        return true;
    }

    /**
     * Resets the simulated player
     */
    public void Reset() throws MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Reset);
        Invalidate(true);
        state.MakeStateTransition(StateModel.STATE_QUORUM_CLEARED);
    }

    /**
     * Invalidates stored keys and calls KeyGen()
     *
     * @throws NoSuchAlgorithmException
     */
    public void GenKeyPair() throws NoSuchAlgorithmException, MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_InitAndGenerateKeyPair);

        this.KeyGen();

        state.MakeStateTransition(StateModel.STATE_KEYGEN_PRIVATEGENERATED);
    }

    /**
     * Generates and stores public and private key; and computes hash of public key
     *
     * @throws NoSuchAlgorithmException
     */
    private void KeyGen() throws NoSuchAlgorithmException {
        SecureRandom rnd = new SecureRandom();
        priv_key_BI = new BigInteger(256, rnd);
        if (MPCTestClient._FIXED_PLAYERS_RNG) {
            System.out.println("WARNING: _FIXED_PLAYERS_RNG == true");
            // If true, don't generate random key, but use fixed one instead
            priv_key_BI = new BigInteger("B346675518084623BC111CC53FF615B152A3F6D1585278370FA1BA0EA160237E".getBytes());
        }

        pub_key_EC = mpcGlobals.G.multiply(priv_key_BI);
        players[CARD_INDEX_THIS].pubKeyValid = true;
        num_pubkeys_count++;

        // Adds public key to Yagg
        Yagg = Yagg.add(pub_key_EC);
        Yagg_shares_count++;

        // computes and stores hash of the pubkey
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(pub_key_EC.getEncoded(false));
        pub_key_Hash = md.digest();
        num_commitments_count++;
    }

    /**
     * Computes and returns Ri,j
     *
     * @param i incrementing request counter
     * @return Ri, j
     * @throws NoSuchAlgorithmException
     */
    public byte[] Gen_Rin(short i, byte[] hostId) throws NoSuchAlgorithmException, MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Sign_RetrieveRandomRi);


        // checks if the counter hasn't been used before == (if the counter is bigger then the previous one)
        if (i <= signature_counter) {
            throw new MPCException("Provided counter is not valid.");
        }

        // stores the counter for later comparison
        signature_counter = i;

        Bignat counter = Util.makeBignatFromValue((int) i);
        ECPoint Rin = mpcGlobals.G.multiply(new BigInteger(PRF(counter, this.secret_seed)));
        return Rin.getEncoded(false);
    }

    /**
     * Checks if public key retrieval is allowed
     *
     * @return
     * @throws MPCException
     */
    public boolean RetrievePubKeyHash() throws MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_RetrieveCommitment);

        // In extreme case, when quorum is of size 1 and StorePubKeyHash() is skipped, the state transition has to happen here
        if (NUM_PLAYERS == 1) {
            state.MakeStateTransition(StateModel.STATE_KEYGEN_COMMITMENTSCOLLECTED);
        }

        return true;
    }

    /**
     * Stores hashes of other player's public key
     *
     * @param playerIndex Index of the player whose hash is being stored
     * @param hash_arr    hash of public key
     * @return
     * @throws MPCException
     */
    public boolean StorePubKeyHash(short playerIndex, byte[] hash_arr) throws MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_StoreCommitment);

        // approves player's index
        if (playerIndex < 0 || playerIndex == CARD_INDEX_THIS || playerIndex >= NUM_PLAYERS) {
            throw new MPCException("Player's index is not valid.");
        }

        // makes sure the player hasn't submitted his pubkey hash before
        if (players[playerIndex].pubKeyHashValid) {
            throw new MPCException("Commitment is already stored.");
        }

        // stores the hash
        players[playerIndex].pubKeyHash = hash_arr;
        players[playerIndex].pubKeyHashValid = true;
        num_commitments_count++;

        if (num_commitments_count == NUM_PLAYERS) {
            state.MakeStateTransition(StateModel.STATE_KEYGEN_COMMITMENTSCOLLECTED);
        }
        return true;
    }

    /**
     * retrieves this player's public key
     *
     * @return public key
     * @throws MPCException
     */
    public byte[] RetrievePubKey() throws MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GetYi);

        if (!players[CARD_INDEX_THIS].pubKeyValid) {
            throw new MPCException("Share is not valid.");
        }

        // In extreme case, when quorum is of size 1 and StorePubKey() is skipped, the state transition has to happen here
        if (NUM_PLAYERS == 1) {
            state.MakeStateTransition(StateModel.STATE_KEYGEN_SHARESCOLLECTED);
            state.MakeStateTransition(StateModel.STATE_KEYGEN_KEYPAIRGENERATED);
        }

        return pub_key_EC.getEncoded(false);
    }

    /**
     * Stores public keys of other players
     *
     * @param playerIndex Index of the player whose public key is being stored
     * @param pub_arr     public key
     * @return
     * @throws MPCException
     */
    public boolean StorePubKey(short playerIndex, byte[] pub_arr) throws MPCException, NoSuchAlgorithmException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_SetYs);

        // makes sure player's index is valid
        if (playerIndex < 0 || playerIndex == CARD_INDEX_THIS || playerIndex >= NUM_PLAYERS) {
            throw new MPCException("Player's index is not valid.");
        }

        // checks that the player hasn't submitted his pubkey before
        if (players[playerIndex].pubKeyValid) {
            throw new MPCException("Share is already stored.");
        }

        // computes the hash of submitted pubkey and compares it to the hash submitted before
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(pub_arr);
        byte[] hash_comp = md.digest();
        if (!Arrays.equals(hash_comp, players[playerIndex].pubKeyHash)) {
            throw new MPCException("Commitment is not valid.");
        }

        // storing pubkey
        players[playerIndex].pubKey = pub_arr;
        players[playerIndex].pubKeyValid = true;
        num_pubkeys_count++;

        // adding submitted pubkey to Yagg
        Yagg = Yagg.add(Util.ECPointDeSerialization(mpcGlobals.curve, pub_arr, 0));
        Yagg_shares_count++;

        // when all players exchanged their pubkeys => makes state transition
        if (num_pubkeys_count == NUM_PLAYERS) {
            state.MakeStateTransition(StateModel.STATE_KEYGEN_SHARESCOLLECTED);
            if (Yagg_shares_count == NUM_PLAYERS) {
                state.MakeStateTransition(StateModel.STATE_KEYGEN_KEYPAIRGENERATED);
            }
        }
        return true;
    }

    /**
     * Since Yagg is computed in storePubkey(), RetrieveAggPubkey() only checks if Yagg is computed
     *
     * @return
     * @throws MPCException
     */
    public boolean RetrieveAggPubKey() throws MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GetY);
        return true;
    }

    /**
     * Signs the byte[] plaintext
     *
     * @param round     incrementing request counter
     * @param Rn        random group element corresponding to the round
     * @param plaintext plaintext to be signed
     * @return signature
     * @throws NoSuchAlgorithmException
     */
    public BigInteger Sign(int round, byte[] Rn, byte[] plaintext) throws NoSuchAlgorithmException, MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Sign);
        Bignat roundBn = Util.makeBignatFromValue(round);
        ECPoint R_EC = Util.ECPointDeSerialization(mpcGlobals.curve, Rn, 0);

        // checks if the counter hasn't been used before == (if the counter is bigger then the previous one)
        if (!signature_counter_Bn.lesser(roundBn)) {
            throw new MPCException("Provided counter is not valid.");
        }
        // stores the counter for later comparison
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
        s_i_BI = s_i_BI.mod(mpcGlobals.n);

        //System.out.println("Simulated: s:        " + Util.bytesToHex(s_i_BI.toByteArray()));
        //System.out.println("Simulated: e:        " + Util.bytesToHex(e) + "\n");
        return s_i_BI;
    }

    //
    // Crypto ops
    //

    /**
     * Encrypts the byte[] plaintext
     *
     * @param plaintext plaintext to be encrypted
     * @return encrypted plaintext
     * @throws MPCException
     */
    public byte[] Encrypt(byte[] plaintext) throws MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Encrypt);

        SecureRandom rnd = new SecureRandom();
        BigInteger rand_r = new BigInteger(256, rnd);
        mpcGlobals.c1 = mpcGlobals.G.multiply(rand_r);
        mpcGlobals.c2 = mpcGlobals.AggPubKey.multiply(rand_r).add(Util.ECPointDeSerialization(mpcGlobals.curve, plaintext, 0));
        return Util.joinArray(mpcGlobals.c1.getEncoded(false), mpcGlobals.c2.getEncoded(false));
    }

    /**
     * Computes this card's decrypt share
     *
     * @param ciphertext El Gamal ciphertext C1
     * @return decryption share
     * @throws MPCException
     */
    public byte[] Decrypt(byte[] ciphertext) throws MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_DecryptShare);

        ECPoint c1 = Util.ECPointDeSerialization(mpcGlobals.curve, ciphertext, 0);
        ECPoint xc1_share = c1.multiply(priv_key_BI);
        return xc1_share.getEncoded(false);
    }

    /**
     * Generates a byte array of random bytes
     *
     * @param length length of the byte array
     * @return a random byte array
     */
    public byte[] GenerateRandom(short length) throws MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GenerateRandomData);
        byte[] randomBytes = new byte[length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(randomBytes);
        return randomBytes;
    }

    /**
     * Invalidates stored keys and initializes necessary variables
     *
     * @param bEraseAllArrays if true, invalidates all variables
     */
    private void Invalidate(boolean bEraseAllArrays) throws MPCException {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Invalidate);

        SecureRandom random = new SecureRandom();

        if (bEraseAllArrays) {
            random.nextBytes(secret_seed);
            priv_key_BI = new BigInteger(256, random);
            pub_key_EC = mpcGlobals.G.multiply(priv_key_BI);
            num_commitments_count = 0;
            num_pubkeys_count = 0;
            Yagg = mpcGlobals.curve.getInfinity();
            Yagg_shares_count = 0;
            hosts.clear();
            hostInitialised = false;
        }

        signature_counter = 0;
        signature_counter_Bn.zero();

        for (Player playerI : players) {
            playerI.pubKeyHashValid = false;
            playerI.pubKeyValid = false;
            if (bEraseAllArrays) {
                // overwrites pubkeys and pubkey hashes of other players
                random.nextBytes(playerI.pubKey);
                random.nextBytes(playerI.pubKeyHash);
            }
        }
        state.MakeStateTransition(StateModel.STATE_QUORUM_CLEARED);
    }

    /**
     * Pseudo random function used for singing
     *
     * @param i    incrementing request number
     * @param seed secret seed
     * @return result of the PRF
     * @throws NoSuchAlgorithmException
     */
    private byte[] PRF(Bignat i, byte[] seed) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.reset();
        md.update(i.as_byte_array());
        md.update(seed);
        return md.digest();
    }


    void VerifyCallerAuthorization(short requestedFunc, byte[] hostId) throws MPCException {
        ByteWrapper hostIdWrapped = new ByteWrapper(hostId);
        if (!hosts.containsKey(hostIdWrapped)) {
            throw new InvalidHostIdException();
        }
        hosts.get(hostIdWrapped).VerifyCallerAuthorization(requestedFunc);
    }

    /**
     * Since arrays don't implement value equality the way we want,
     * hostID will be wrapped inside this class. This way we can use
     * a byte array as a key in a map.
     */
    static class ByteWrapper {
        public byte[] hostId;

        public ByteWrapper(byte[] hostId) {
            this.hostId = hostId;
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(hostId);
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof ByteWrapper)) {
                return false;
            }
            return Arrays.equals(hostId, ((ByteWrapper) o).hostId);
        }

    }

    class Player {
        public byte[] pubKey = null;
        public boolean pubKeyValid = false;
        public byte[] pubKeyHash = null;
        public boolean pubKeyHashValid = false;
    }
}
