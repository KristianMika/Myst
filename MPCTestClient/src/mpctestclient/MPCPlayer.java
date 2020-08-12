package mpctestclient;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.PrivateKey;


/**
 * Interface that contains cryptographic and card management methods
 *
 * @author Petr Svenda
 */
public interface MPCPlayer {

    /**
     * Sets authorisation public key and it's permissions - creates an ACL
     *
     * @param pubkey          as an ECpoint
     * @param hostPermissions compressed short representing user's permissions
     * @param quorumIndex     index of the quorum
     * @param hostId          host's ID
     * @param hostPrivKey     host's private key
     * @return true if no error occurs
     * @throws Exception is fails
     */
    boolean SetHostAuthPubkey(ECPoint pubkey, short hostPermissions, short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception;

    /**
     * Gets e value
     *
     * @param quorumIndex index
     * @return BigInteger e
     */
    BigInteger GetE(short quorumIndex);

    /**
     * Sends a request for retrieving Rin
     *
     * @param quorumIndex quorum index
     * @param i           round counter
     * @param hostId      host's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @return Rin as a byte array
     * @throws Exception if fails
     */
    byte[] Gen_Rin(short quorumIndex, short i, byte[] hostId, PrivateKey hostPrivKey) throws Exception;

    /**
     * Gets the public key of the card
     *
     * @param quorumIndex quorum index
     * @return public key as an ECpoint
     */
    ECPoint GetPubKey(short quorumIndex);

    /**
     * Gets the aggregated public key
     *
     * @param quorumIndex quorum index
     * @return aggregated public key as an ECpoint
     */
    ECPoint GetAggregatedPubKey(short quorumIndex);

    /**
     * Gets this player's index
     *
     * @param quorumIndex quorum index
     * @return this player's index as a short
     */
    short GetPlayerIndex(short quorumIndex);

    /**
     * Gets hash of the card's public key
     *
     * @param quorumIndex quorum index
     * @return hash of the card's cublic key as a byte array
     */
    byte[] GetPubKeyHash(short quorumIndex);

    /**
     * Sends a command for setting up a card with necessary information
     *
     * @param quorumIndex     quorum index
     * @param numPlayers      number of players that will participate
     * @param thisPlayerIndex index of this player
     * @param hostId          host's ID
     * @param hostPrivKey     host's private key used for packet signature
     * @return true if no error occurs
     * @throws Exception if fails
     */
    boolean Setup(short quorumIndex, short numPlayers, short thisPlayerIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception;

    /**
     * Sends a command for resetting a card to the uninitialised state
     *
     * @param quorumIndex quorum index
     * @param hostId      host's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @return true if no error occurs
     * @throws Exception if fails
     */
    boolean Reset(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception;

    /**
     * Sends a command for removing a quorum
     *
     * @param quorumIndex quorum index
     * @param hostId      host's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @return true if no error occurs
     * @throws Exception if fails
     */
    boolean Remove(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception;


    /**
     * Returns the current signature counter. A host has to submit a bigger value in the next sign request.
     *
     * @param quorumIndex quorum index
     * @param hostId      host's id
     * @param hostPrivKey hosts's private key used for packet signature
     * @return Current signature counter as a BigInteger
     * @throws Exception if fails
     */
    BigInteger GetCurrentCounter(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception;


    /**
     * @param quorumIndex quorum index
     * @param round       round counter
     * @param Rn          random number
     * @param plaintext   plaintext to be signed
     * @param hostId      hosts's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @return card's signature share as a bigInteger
     * @throws Exception if fails
     */
    BigInteger Sign(short quorumIndex, int round, byte[] Rn, byte[] plaintext, byte[] hostId, PrivateKey hostPrivKey) throws Exception;

    /**
     * Sends a command for generating new private key and computing the card's public key
     *
     * @param quorumIndex quorum index
     * @param hostId      host's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @return true if no error occurs
     * @throws Exception if fails
     */
    boolean GenKeyPair(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception;

    /**
     * Sends a request for the hash of the card's public key
     *
     * @param quorumIndex quorum index
     * @param hostId      host's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @return true if no error occurs
     * @throws Exception if fails
     */
    boolean RetrievePubKeyHash(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception;

    /**
     * Sends the hash of "playerIndex's" public key to this card to store it
     *
     * @param quorumIndex quorum index
     * @param playerIndex index of the owner of the hash
     * @param hash_arr    hash as a byte array
     * @param hostId      host's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @return true if no error occurs
     * @throws Exception if fails
     */
    boolean StorePubKeyHash(short quorumIndex, short playerIndex, byte[] hash_arr, byte[] hostId, PrivateKey hostPrivKey) throws Exception;

    /**
     * Sends a request for the card's public key
     *
     * @param quorumIndex quorum index
     * @param hostId      host's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @param mpcGlobals  object containing cryptographic parameters
     * @return card's public key as a byte array
     * @throws Exception if fails
     */
    byte[] RetrievePubKey(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey, MPCGlobals mpcGlobals) throws Exception;

    /**
     * Sends the "playerIndex's" public key to this card to store it
     *
     * @param quorumIndex quorum index
     * @param playerIndex player's index
     * @param pub_arr     public key to be sent as a byte array
     * @param hostId      host's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @return true if no error occurs
     * @throws Exception if fails
     */
    boolean StorePubKey(short quorumIndex, short playerIndex, byte[] pub_arr, byte[] hostId, PrivateKey hostPrivKey) throws Exception;

    /**
     * Sends a request for the aggregated public key
     *
     * @param quorumIndex quorum index
     * @param hostId      host's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @return true if no error occurs
     * @throws Exception if fails
     */
    boolean RetrieveAggPubKey(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey) throws Exception;

    /**
     * Sends a request for encryption.
     *
     * @param quorumIndex quorum index
     * @param plaintext   plain text to be encrypted
     * @param hostId      host's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @return cipher text as a byte array
     * @throws Exception if fails
     */
    byte[] Encrypt(short quorumIndex, byte[] plaintext, byte[] hostId, PrivateKey hostPrivKey) throws Exception;

    /**
     * Sends a request for decryption.
     *
     * @param quorumIndex quorum index
     * @param ciphertext  cipher text to be decrypted
     * @param hostId      host's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @return decrypt share as a byte array
     * @throws Exception if fails
     */
    byte[] Decrypt(short quorumIndex, byte[] ciphertext, byte[] hostId, PrivateKey hostPrivKey) throws Exception;


    /**
     * Sends a request for random byte array generation.
     *
     * @param quorumIndex quorum index
     * @param hostId      host's ID
     * @param hostPrivKey hosts's private key used for packet signature
     * @param numOfBytes  length of the requested array
     * @return received random byte array
     * @throws Exception if fails
     */
    byte[] GenerateRandom(short quorumIndex, byte[] hostId, PrivateKey hostPrivKey, short numOfBytes) throws Exception;

    void disconnect();
}
