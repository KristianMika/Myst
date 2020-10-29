package mpc;

/**
 *
 * @author Petr Svenda
 */
public class Consts {
    // Manually updated version of corresponding git commit
    public final static byte[] GIT_COMMIT_MANUAL = {(byte) 0x01, (byte) 0x14, (byte) 0x20, (byte) 0xaf};

    // MAIN INSTRUCTION CLASS
    public final static byte CLA_MPC				= (byte) 0xB0;

    // INStructions
    // Card Management

    public final static byte INS_QUORUM_SETUP_NEW		= (byte) 0x01;
    public final static byte INS_PERSONALIZE_GETCARDINFO        = (byte) 0x02;
    public final static byte INS_QUORUM_RESET                   = (byte) 0x03;
    public final static byte INS_PERF_SETSTOP                   = (byte) 0x04;
    public final static byte INS_SET_BACKDOORED_EXAMPLE         = (byte) 0x05;
    public final static byte INS_TESTECC                        = (byte) 0x06;
    public final static byte INS_QUORUM_REMOVE                  = (byte) 0x07;

    public final static byte INS_PERSONALIZE_INITIALIZE         = (byte) 0x08;
    public final static byte INS_PERSONALIZE_SET_USER_AUTH_PUBKEY = (byte) 0x09;


    // KeyGen Operations
    public final static byte INS_KEYGEN_INIT			= (byte) 0x10;
    public final static byte INS_KEYGEN_RETRIEVE_COMMITMENT	= (byte) 0x11;
    public final static byte INS_KEYGEN_STORE_COMMITMENT	= (byte) 0x12;
    public final static byte INS_KEYGEN_STORE_PUBKEY		= (byte) 0x13;
    public final static byte INS_KEYGEN_RETRIEVE_PUBKEY         = (byte) 0x14;
    public final static byte BUGBUG_INS_KEYGEN_RETRIEVE_PRIVKEY	= (byte) 0x15;
    public final static byte INS_KEYGEN_RETRIEVE_AGG_PUBKEY     = (byte) 0x16;

    public final static byte INS_KEYPROPAGATION_RETRIEVE_PRIVKEY_SHARES = (byte) 0x20;
    public final static byte INS_KEYPROPAGATION_SET_PRIVKEY_SHARES      = (byte) 0x21;
    public final static byte INS_KEYPROPAGATION_RECONSTRUCT_PRIVATEKEY  = (byte) 0x22;


    // Encryption/Decryption Operations
    public final static byte INS_ENCRYPT			= (byte) 0x50;
    public final static byte INS_DECRYPT			= (byte) 0x51;
    public final static byte INS_ECDH_EXCHANGE = (byte) 0x52;


    public final static byte INS_GENERATE_RANDOM                = (byte) 0x55;

    // Signing Operations
    // 0x60 to 0x6F and 0x90 to 0x9F are not allowed according to ISO 7816-3 and -4
    //public final static byte INS_SIGN_INIT			= (byte) 0x70; 
    //public final static byte INS_SIGN_RETRIEVE_HASH		= (byte) 0x71;
    //public final static byte INS_SIGN_STORE_HASH		= (byte) 0x72;
    //public final static byte INS_SIGN_STORE_RI			= (byte) 0x73;
    //public final static byte INS_SIGN_STORE_RI_N_HASH		= (byte) 0x74;
    public final static byte INS_SIGN_RETRIEVE_RI		= (byte) 0x75;
    //public final static byte INS_SIGN_RETRIEVE_RI_N_HASH	= (byte) 0x76;
    //public final static byte BUGBUG_INS_SIGN_RETRIEVE_KI	= (byte) 0x77; // BUGBUG: only for testing, remove 
    //public final static byte BUGBUG_INS_SIGN_RETRIEVE_R		= (byte) 0x78; // BUGBUG: only for testing, remove 
    public final static byte INS_SIGN                           = (byte) 0x79;
    public final static byte INS_SIGN_GET_CURRENT_COUNTER       = (byte) 0x7a;
    public final static byte INS_SIGN_INIT                      = (byte) 0x7b;


    //Low level Operations
    public final static byte INS_ADDPOINTS						= (byte) 0x80;

    // Custom error response codes
    public static final short SW_SUCCESS                        = (short) 0x9000;
    public static final short SW_TOOMANYPLAYERS                 = (short) 0x8000;
    public static final short SW_INCORRECTSTATE                 = (short) 0x8001;
    public static final short SW_INVALIDCOMMITMENT              = (short) 0x8002;
    public static final short SW_INVALIDYSHARE                  = (short) 0x8003;
    public static final short SW_SHAREALREADYSTORED             = (short) 0x8004;
    public static final short SW_CANTALLOCATE_BIGNAT            = (short) 0x8005;
    public static final short SW_INVALIDPOINTTYPE               = (short) 0x8006;
    public static final short SW_NOTSUPPORTEDYET                = (short) 0x8007;
    public static final short SW_INTERNALSTATEMISMATCH          = (short) 0x8008;
    public static final short SW_INVALIDPLAYERINDEX             = (short) 0x8009;
    public static final short SW_UNKNOWNSTATE                   = (short) 0x800a;
    public static final short SW_UNKNOWNFUNCTION                = (short) 0x800b;
    public static final short SW_COMMITMENTALREADYSTORED        = (short) 0x800c;
    public static final short SW_INCORRECTSTATETRANSITION       = (short) 0x800d;
    public static final short SW_FUNCTINNOTALLOWED              = (short) 0x800e;
    public static final short SW_INVALIDPACKETSTRUCTURE         = (short) 0x800d;
    public static final short SW_INVALIDQUORUMINDEX             = (short) 0x800e;
    public static final short SW_INVALIDCOMMITMENTLENGTH        = (short) 0x800f;
    public static final short SW_INVALIDMESSAGELENGTH           = (short) 0x8010;
    public static final short SW_INVALIDCOUNTER                 = (short) 0x8011;
    public static final short SW_INCORRECTJCMATHLIBSETTINGS     = (short) 0x8012;
    public static final short SW_TOOMANYHOSTS                   = (short) 0x8013;
    public static final short SW_HOSTNOTALLOWED                 = (short) 0x8014;
    public static final short SW_INVALID_HOST_ID                = (short) 0x8015;
    public static final short SW_INVALID_PACKET_SIGNATURE       = (short) 0x8016;
    public static final short SW_HOST_NOT_INITIALISED           = (short) 0x8017;
    public static final short SW_HOST_ALREADY_INITIALISED       = (short) 0x8018;
    public static final short SW_DH_EXCHANGE_SKIPPED            = (short) 0x8019;
    public static final short SW_DUPLICATE_HOST_ID              = (short) 0x801a;
    public static final short SW_APPLET_LOCKED                  = (short) 0x801b;



    public static final short SIGN_COUNTER_LENGTH = (short) 2;
    public static final short PACKET_SIZE_OFFSET = (short) 4;
    public static final short SHORT_SIZE = (short) 2;
    public static final short BYTE_SIZE = (short) 1;
    public static final short HOST_ID_SIZE = 4;
    public static final short APDU_SIG_NONCE_SIZE = (short) 10;



    public static final short PACKET_PARAMS_OPCODE_OFFSET = (short) 0;
    public static final short PACKET_PARAMS_LENGTH_OFFSET = (short) (PACKET_PARAMS_OPCODE_OFFSET + 1);
    public static final short PACKET_PARAMS_CTXINDEX_OFFSET = (short) (PACKET_PARAMS_LENGTH_OFFSET + 2);

    // General params
    public static final short PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET = (short) 0;
    // SetupNewQuorum params
    public static final short PACKET_PARAMS_SETUPNEWQUORUM_NUMPLAYERS_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_SETUPNEWQUORUM_THISPLAYERINDEX_OFFSET = (short) (PACKET_PARAMS_SETUPNEWQUORUM_NUMPLAYERS_OFFSET + 2);
    public static final short PACKET_PARAMS_SETUPNEWQUORUM_HOSTID_OFFSET = (short) (PACKET_PARAMS_SETUPNEWQUORUM_THISPLAYERINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_SETUPNEWQUORUM_SIGNATURE_OFFSET = (short) (PACKET_PARAMS_SETUPNEWQUORUM_HOSTID_OFFSET + HOST_ID_SIZE);
    // RemoveQuorum params
    public static final short PACKET_PARAMS_REMOVEQUORUM_HOSTID_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_REMOVEQUORUM_SIGNATURE_OFFSET = (short) (PACKET_PARAMS_REMOVEQUORUM_HOSTID_OFFSET + HOST_ID_SIZE);
    // QuorumReset params
    public static final short PACKET_PARAMS_QUORUMRESET_HOSTID_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_QUORUMRESET_SIGNATURE_OFFSET = (short) (PACKET_PARAMS_QUORUMRESET_HOSTID_OFFSET + HOST_ID_SIZE);
    // PersonaliseSetUserAuthPubkey
    public static final short PACKET_PARAMS_SETUSERAUTHPUBKEY_PERM_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_SETUSERAUTHPUBKEY_HOSTID_OFFSET = (short) (PACKET_PARAMS_SETUSERAUTHPUBKEY_PERM_OFFSET + 2);
    public static final short PACKET_PARAMS_SETUSERAUTHPUBKEY_PUBKEY_OFFSET = (short) (PACKET_PARAMS_SETUSERAUTHPUBKEY_HOSTID_OFFSET + HOST_ID_SIZE);
    public static final short PACKET_PARAMS_SETUSERAUTHPUBKEY_SIGNATURE_OFFSET = (short) (PACKET_PARAMS_SETUSERAUTHPUBKEY_PUBKEY_OFFSET + 65);
    // KeyGen_Init
    public static final short PACKET_PARAMS_KEYGENINIT_HOSTID_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_KEYGENINIT_NONCE_OFFSET = (short) (PACKET_PARAMS_KEYGENINIT_HOSTID_OFFSET + HOST_ID_SIZE);
    public static final short PACKET_PARAMS_KEYGENINIT_SIGNATURE_OFFSET = (short) (PACKET_PARAMS_KEYGENINIT_NONCE_OFFSET + APDU_SIG_NONCE_SIZE);
    // KeyGen_RetrieveCommitment: incoming APDU
    public static final short PACKET_PARAMS_RETRIEVECOMMITMENT_IN_HOSTID_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_RETRIEVECOMMITMENT_IN_SIGNATURE_OFFSET = (short) (PACKET_PARAMS_RETRIEVECOMMITMENT_IN_HOSTID_OFFSET + HOST_ID_SIZE);
    // KeyGen_RetrieveCommitment: outgoing APDU
    public static final short PACKET_PARAMS_RETRIEVECOMMITMENT_OUT_DATA_OFFSET = (short) (PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET + SHORT_SIZE);
    // KeyGen_StoreCommitment params
    public static final short PACKET_PARAMS_KEYGENSTORECOMMITMENT_PLAYERID_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_KEYGENSTORECOMMITMENT_COMMITMENTLENGTH_OFFSET = (short) (PACKET_PARAMS_KEYGENSTORECOMMITMENT_PLAYERID_OFFSET + 2);
    public static final short PACKET_PARAMS_KEYGENSTORECOMMITMENT_HOSTID_OFFSET = (short) (PACKET_PARAMS_KEYGENSTORECOMMITMENT_COMMITMENTLENGTH_OFFSET + 2);
    public static final short PACKET_PARAMS_KEYGENSTORECOMMITMENT_NONCE_OFFSET = (short) (PACKET_PARAMS_KEYGENSTORECOMMITMENT_HOSTID_OFFSET + HOST_ID_SIZE);
    public static final short PACKET_PARAMS_KEYGENSTORECOMMITMENT_COMMITMENT_OFFSET = (short) (PACKET_PARAMS_KEYGENSTORECOMMITMENT_NONCE_OFFSET + APDU_SIG_NONCE_SIZE);
    //KeyGen_RetrievePublicKey: incoming apdu
    public static final short PACKET_PARAMS_RETRIEVEPUBKEY_IN_HOSTID_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_RETRIEVEPUBKEY_IN_SIGNATURE_OFFSET = (short) (PACKET_PARAMS_RETRIEVEPUBKEY_IN_HOSTID_OFFSET + HOST_ID_SIZE);
    //KeyGen_RetrievePublicKey: outgoing apdu
    public static final short PACKET_PARAMS_RETRIEVEPUBKEY_OUT_DATA_OFFSET = (short) (PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET + SHORT_SIZE);
    // KeyGen_StorePublicKey params
    public static final short PACKET_PARAMS_KEYGENSTOREPUBKEY_PLAYERID_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_KEYGENSTOREPUBKEY_PUBKEYLENGTH_OFFSET = (short) (PACKET_PARAMS_KEYGENSTOREPUBKEY_PLAYERID_OFFSET + 2);
    public static final short PACKET_PARAMS_KEYGENSTOREPUBKEY_HOSTID_OFFSET = (short) (PACKET_PARAMS_KEYGENSTOREPUBKEY_PUBKEYLENGTH_OFFSET + 2);
    public static final short PACKET_PARAMS_KEYGENSTOREPUBKEY_NONCE_OFFSET = (short) (PACKET_PARAMS_KEYGENSTOREPUBKEY_HOSTID_OFFSET + HOST_ID_SIZE);
    public static final short PACKET_PARAMS_KEYGENSTOREPUBKEY_PUBKEY_OFFSET = (short) (PACKET_PARAMS_KEYGENSTOREPUBKEY_NONCE_OFFSET + APDU_SIG_NONCE_SIZE);
    // KeyGen_RetrieveAggregatedPublicKey: incoming APDU
    public static final short PACKET_PARAMS_RETRIEVEYAGG_IN_HOSTID_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_RETRIEVEYAGG_IN_SIGNATURE_OFFSET = (short) (PACKET_PARAMS_RETRIEVEYAGG_IN_HOSTID_OFFSET + HOST_ID_SIZE);
    // KeyGen_RetrieveAggregatedPublicKey: outgoing APDU
    public static final short PACKET_PARAMS_RETRIEVEYAGG_OUT_DATA_OFFSET = (short) (PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET + SHORT_SIZE);
    // EncryptData params: incoming APDU
    public static final short PACKET_PARAMS_ENCRYPT_IN_DATALENGTH_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_ENCRYPT_IN_HOSTID_OFFSET = (short) (PACKET_PARAMS_ENCRYPT_IN_DATALENGTH_OFFSET + 2);
    public static final short PACKET_PARAMS_ENCRYPT_IN_DATA_OFFSET = (short) (PACKET_PARAMS_ENCRYPT_IN_HOSTID_OFFSET + HOST_ID_SIZE);
    // EncryptData params: outgoing APDU
    public static final short PACKET_PARAMS_ENCRYPT_OUT_CIPHERLENGTH_OFFSET = (short) (0);
    public static final short PACKET_PARAMS_ENCRYPT_OUT_CIPHER_OFFSET = (short) (PACKET_PARAMS_ENCRYPT_OUT_CIPHERLENGTH_OFFSET + SHORT_SIZE);
    // DecryptData params: incoming apdu
    public static final short PACKET_PARAMS_DECRYPT_IN_DATALENGTH_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_DECRYPT_IN_HOSTID_OFFSET = (short) (PACKET_PARAMS_DECRYPT_IN_DATALENGTH_OFFSET + SHORT_SIZE);
    public static final short PACKET_PARAMS_DECRYPT_IN_DATA_OFFSET = (short) (PACKET_PARAMS_DECRYPT_IN_HOSTID_OFFSET + HOST_ID_SIZE);
    // DecryptData params: outgoing apdu
    public static final short PACKET_PARAMS_DECRYPT_OUT_DATA_OFFSET = (short) (PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET + SHORT_SIZE);
    // Sign_RetrieveRandomRi params: incoming apdu
    public static final short PACKET_PARAMS_SIGNRETRIEVERI_IN_COUNTER_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_SIGNRETRIEVERI_IN_HOSTID_OFFSET = (short) (PACKET_PARAMS_SIGNRETRIEVERI_IN_COUNTER_OFFSET + SHORT_SIZE);
    // Sign_RetrieveRandomRi params: outgoing apdu
    public static final short PACKET_PARAMS_SIGNRETRIEVERI_OUT_DATA_OFFSET = (short) (PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET + SHORT_SIZE);
    // Sign params: incoming apdu
    public static final short PACKET_PARAMS_SIGN_IN_COUNTER_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_SIGN_IN_DATALENGTH_OFFSET = (short) (PACKET_PARAMS_SIGN_IN_COUNTER_OFFSET + SIGN_COUNTER_LENGTH);
    public static final short PACKET_PARAMS_SIGN_IN_HOSTID_OFFSET = (short) (PACKET_PARAMS_SIGN_IN_DATALENGTH_OFFSET + SHORT_SIZE);
    public static final short PACKET_PARAMS_SIGN_IN_DATA_OFFSET = (short) (PACKET_PARAMS_SIGN_IN_HOSTID_OFFSET + HOST_ID_SIZE);
    // Sign params: outgoing apdu
    public static final short PACKET_PARAMS_SIGN_OUT_DATA_OFFSET = (short) (PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET + SHORT_SIZE);
    // GenerateRandom params: incoming apdu
    public static final short PACKET_PARAMS_GENERATERANDOM_IN_LENGTH_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + SHORT_SIZE);
    public static final short PACKET_PARAMS_GENERATERANDOM_IN_HOSTID_OFFSET = (short) (PACKET_PARAMS_GENERATERANDOM_IN_LENGTH_OFFSET + SHORT_SIZE);
    // GenerateRandom params: outgoing apdu
    public static final short PACKET_PARAMS_GENERATERANDOM_OUT_DATA_OFFSET = (short) (PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET + SHORT_SIZE);
    // exchangeKey params: incoming apdu
    public static final short PACKET_PARAMS_EXCHANGEKEY_IN_KEYLENGTH_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + SHORT_SIZE);
    public static final short PACKET_PARAMS_EXCHANGEKEY_IN_HOSTID_OFFSET = (short) (PACKET_PARAMS_EXCHANGEKEY_IN_KEYLENGTH_OFFSET + SHORT_SIZE);
    public static final short PACKET_PARAMS_EXCHANGEKEY_IN_HOSTKEY_OFFSET = (short) (PACKET_PARAMS_EXCHANGEKEY_IN_HOSTID_OFFSET + HOST_ID_SIZE);
    // exchangeKey params: outgoing apdu
    public static final short PACKET_PARAMS_EXCHANGEKEY_OUT_CARDKEY_OFFSET = (short) (PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET + SHORT_SIZE);


    public static final short PACKET_PARAMS_SET_USER_AUTH_PUBKEY_ACLBYTE = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + 2);
    public static final short PACKET_PARAMS_SET_USER_AUTH_PUBKEY = (short) (PACKET_PARAMS_SET_USER_AUTH_PUBKEY_ACLBYTE + 2);
    // GenerateSuccessApdu params
    public static final short PACKET_PARAMS_SUCCESS_APDU_NONCE_OFFSET = (short) (PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET + SHORT_SIZE);
    // GetCurrentCounter: incoming APDU
    public static final short PACKET_PARAMS_GETCURRENTCOUNTER_IN_HOSTID_OFFSET = (short) (PACKET_PARAMS_CTXINDEX_OFFSET + SHORT_SIZE);
    public static final short PACKET_PARAMS_GETCURRENTCOUNTER_IN_SIGNATURE_OFFSET = (short) (PACKET_PARAMS_GETCURRENTCOUNTER_IN_HOSTID_OFFSET + HOST_ID_SIZE);
    // GetCurrentCounter: outgoing APDU
    public static final short PACKET_PARAMS_GETCURRENTCOUNTER_OUT_COUNTER_OFFSET = (short) (PACKET_PARAMS_APDU_OUT_DATALENGTH_OFFSET + SHORT_SIZE);

    // Performance-related debugging response codes
    public static final short PERF_DECRYPT                      = (short) 0x7770;
    public static final short PERF_ENCRYPT                      = (short) 0x6660;
    public static final short PERF_SIGN                         = (short) 0x5550;

    // Global applet settings
    public static final short MAX_NUM_PLAYERS                   = (short) 15;   // Maximum number of allowed players
    public static final short MAX_NUM_HOSTS                     = (short) 5; // Maximum number of allowed hosts
    public static final short EXCEPTION_COUNT_LIMIT             = (short) 15;

    public final static boolean COMPUTE_Y_ONTHEFLY = true; // on-the-fly computation of aggregated pulic key is only option
    public final static boolean PLAYERS_IN_RAM = true; // if true, player (participant) info is stored in RAM => faster, consuming RAM and will NOT survive card reset
    public final static boolean IS_BACKDOORED_EXAMPLE = false; // if true, then applet will not follow protocol but generates backdoored applet instead


    // TLV types
    public final static byte TLV_TYPE_CARDUNIQUEDID    = (byte) 0x40;
    public final static byte TLV_TYPE_KEYPAIR_STATE    = (byte) 0x41;
    public final static byte TLV_TYPE_EPHIMERAL_STATE  = (byte) 0x42;
    public final static byte TLV_TYPE_MEMORY           = (byte) 0x43;
    public final static byte TLV_TYPE_COMPILEFLAGS     = (byte) 0x44;
    public final static byte TLV_TYPE_GITCOMMIT         = (byte) 0x45;
    public final static byte TLV_TYPE_EXAMPLEBACKDOOR = (byte) 0x46;
    public final static byte TLV_TYPE_MPCINPUTPACKET = (byte) 0x47;
    public final static byte TLV_TYPE_CARDINDEX = (byte) 0x48;

    // Lengths
    public static final byte CARD_ID_LONG_LENGTH = (byte) 16;   // Length of unique card ID generated during applet install

    public static final short BASIC_ECC_LENGTH = (short) 32; // 32 => 256b ECC
    public static final short SHARE_BASIC_SIZE = BASIC_ECC_LENGTH;
    public static final short SHARE_DOUBLE_SIZE = (short) (2 * SHARE_BASIC_SIZE);           // intermediate result of multiplication operation with shares (double bit length)
    public static final short SHARE_DOUBLE_SIZE_CARRY = (short) (SHARE_DOUBLE_SIZE + 1);    // double intermediate result + 1 byte carry
    public static final short PUBKEY_YS_SHARE_SIZE = SHARE_DOUBLE_SIZE_CARRY;    // double intermediate result + 1 byte carry
    public static final short SECRET_SEED_SIZE = BASIC_ECC_LENGTH;
    public static final short HOST_BLOCK_SIZE = SHORT_SIZE + PUBKEY_YS_SHARE_SIZE; // Size of a pair of a public key and an acl short
    public static final short IV_LEN = (short) 16;
    public static final short ACL_SIZE = (short) 2;
    public static final short AES_KEY_LEN = (short) 16;



    public static final short MAX_QUORUMS = 1; // Maximum number of separate quorums this card can participate in

}
