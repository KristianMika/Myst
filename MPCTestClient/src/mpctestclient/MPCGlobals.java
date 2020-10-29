package mpctestclient;

import mpc.jcmathlib;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.Security;

/**
 * @author Petr Svenda
 */
public class MPCGlobals {

    public ECCurve curve;
    public BigInteger p;
    public BigInteger a;
    public BigInteger b;
    public BigInteger n;
    public ECPoint G;
    public ECParameterSpec ecSpec;

    public BigInteger secret = BigInteger.valueOf(0);
    public ECPoint AggPubKey;
    public ECPoint R_EC;

    public ECPoint c1;
    public ECPoint c2;
    public ECPoint[][] Rands;


    public MPCGlobals() {
        prepareECCurve();
    }

    /**
     * Sets globally accessible curve parameters that are used in computations
     */
    void prepareECCurve() {
        p = new BigInteger(Util.bytesToHex(jcmathlib.SecP256r1.p), 16);
        a = new BigInteger(Util.bytesToHex(jcmathlib.SecP256r1.a), 16);
        b = new BigInteger(Util.bytesToHex(jcmathlib.SecP256r1.b), 16);
        curve = new ECCurve.Fp(p, a, b);
        G = Util.ECPointDeSerialization(curve, jcmathlib.SecP256r1.G, 0);
        n = new BigInteger(Util.bytesToHex(jcmathlib.SecP256r1.r), 16); // also noted as r
        ecSpec = new ECParameterSpec(curve, G, n);
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
}
