package mpctestclient;


import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;


/**
 * The {@link Host}  class represents a host that submits queries to cards.
 *
 * @author Kristian Mika
 */
public class Host {
    public byte[] host_id;
    public short permissions;
    public BigInteger privateKey;
    public ECPoint publicKey;
    public PrivateKey privateKeyObject;

    public Host(short[] permissions, MPCGlobals mpcGlobals) throws Exception {
        this.permissions = compressACL(permissions);
        generateKeys(mpcGlobals);
        host_id = Arrays.copyOfRange(publicKey.getEncoded(false), 0, 4);
    }

    /**
     * Generates this host's keys
     * @param mpcGlobals
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public void generateKeys(MPCGlobals mpcGlobals) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        SecureRandom random = new SecureRandom();

        privateKey = new BigInteger(256, random);
        publicKey = mpcGlobals.G.multiply(privateKey);

        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        org.bouncycastle.jce.spec.ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("SecP256r1");
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(privateKey, spec);

        privateKeyObject = keyFactory.generatePrivate(ecPrivateKeySpec);
    }

    /**
     * Permissions are compressed into a short which is later sent to a card
     *
     * @param permissions an array of shorts
     * @return compressed acl
     */
    public static short compressACL(short[] permissions) {
        short aclShort = 0x0000;
        for (short permission : permissions) {
            aclShort = (short) (aclShort | permission);
        }
        return aclShort;
    }

}
