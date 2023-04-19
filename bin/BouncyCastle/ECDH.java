// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019

import java.security.KeyFactory;
import java.math.BigInteger;
import java.security.Security;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPoint;
import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;

public class ECDH
{
    public static byte[] exchange(String curveName, String ada, String axb, String ayb) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        KeyFactory eckf = KeyFactory.getInstance("EC", "BC");
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(curveName);
        ECParameterSpec spec = new ECNamedCurveSpec(curveName, parameterSpec.getCurve(), parameterSpec.getG(), parameterSpec.getN(), parameterSpec.getH(), parameterSpec.getSeed());

        // A's key pair
        BigInteger da = new BigInteger(ada, 16);

        org.bouncycastle.math.ec.ECPoint ApubpBC = parameterSpec.getG().multiply(da).normalize();
        BigInteger xa = ApubpBC.getXCoord().toBigInteger();
        BigInteger ya = ApubpBC.getYCoord().toBigInteger();
        System.out.println(xa.toString(16));
        System.out.println(ya.toString(16));
        ECPoint Apubp = new ECPoint(xa, ya);

        ECPublicKey Apub = (ECPublicKey) eckf.generatePublic(new ECPublicKeySpec(Apubp, spec));

        ECPrivateKey Apriv = (ECPrivateKey) eckf.generatePrivate(new ECPrivateKeySpec(da, spec));

        // B's key pair
        BigInteger xb = new BigInteger(axb, 16);
        BigInteger yb = new BigInteger(ayb, 16);

        ECPoint point = new ECPoint(xb, yb);
        ECPublicKey Bpub = (ECPublicKey) eckf.generatePublic(new ECPublicKeySpec(point, spec));

        // Key exchange
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
		ka.init(Apriv);
		ka.doPhase(Bpub, true);
		byte [] secret = ka.generateSecret();

        return secret;

    }


    /* Arguments in order :
        - curve name : The name of the curve : P-192, P-224, P-256, P-384, P-521
        - da : A's private key in hexadecimal form
        - xb : B's public key's X coordinate in hexadecimal form
        - yb : B's public key's Y coordinate in hexadecimal form
    */
    public static void main(String[] args)
    {

        if (args.length != 4) {
            Util.handleError("Invalid argument number.");
        }

        try {
            byte[] secret = exchange(args[0], args[1], args[2], args[3]);
            System.out.println(Util.stoh(secret));
        }
        catch (Exception e) {
            System.err.println(e);
            Util.handleError("An exception has occured.");
        }

    }
}