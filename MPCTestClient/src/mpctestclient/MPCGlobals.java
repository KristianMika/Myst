package mpctestclient;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;

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
    public ECPoint[] Rands;

    ArrayList<MPCPlayer> players = new ArrayList<>();
}
