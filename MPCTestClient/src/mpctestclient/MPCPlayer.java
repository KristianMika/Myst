package mpctestclient;

import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;
import java.security.PrivateKey;

import org.bouncycastle.math.ec.ECPoint;


/**
 *
 * @author Petr Svenda
 */
public interface MPCPlayer {

    public boolean SetHostAuthPubkey(ECPoint pubkey,short hostPermissions, short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public BigInteger GetE(short quorumIndex);

    public byte[] Gen_Rin(short quorumIndex, short i, byte hostIndex, PrivateKey hostPrivKey) throws NoSuchAlgorithmException, Exception;

    public ECPoint GetPubKey(short quorumIndex);

    public ECPoint GetAggregatedPubKey(short quorumIndex);

    public short GetPlayerIndex(short quorumIndex);

    public byte[] GetPubKeyHash(short quorumIndex);

    public boolean Setup(short quorumIndex, short numPlayers, short thisPlayerIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public boolean Reset(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public boolean Remove(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public BigInteger Sign(short quorumIndex, int round, byte[] Rn, byte[] plaintext, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public boolean GenKeyPair(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public boolean RetrievePubKeyHash(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public boolean StorePubKeyHash(short quorumIndex, short playerIndex, byte[] hash_arr, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public byte[] RetrievePubKey(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public boolean StorePubKey(short quorumIndex, short playerIndex, byte[] pub_arr, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public boolean RetrieveAggPubKey(short quorumIndex, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public byte[] Encrypt(short quorumIndex, byte[] plaintext, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public byte[] Decrypt(short quorumIndex, byte[] ciphertext, byte hostIndex, PrivateKey hostPrivKey) throws Exception;

    public void disconnect();
}
