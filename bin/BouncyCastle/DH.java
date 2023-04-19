// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019

import java.security.KeyPair;
import java.security.KeyFactory;
import java.math.BigInteger;
import java.util.Arrays;
import java.security.Security;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

public class DH
{
    public static byte[] exchange(String p, String g, String ada, String adb) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        KeyFactory dhKeyFact = KeyFactory.getInstance("DH", "BC");

        BigInteger P = new BigInteger(p, 16);
        BigInteger G = new BigInteger(g, 16);

        DHParameterSpec dhSpec = new DHParameterSpec(P, G);

        // A's key pair
        BigInteger da = new BigInteger(ada, 16);
        BigInteger ya = G.modPow(da, P);
        System.out.println(ya.toString(16));

        DHPublicKeySpec ApubSpec = new DHPublicKeySpec(ya, dhSpec.getP(), dhSpec.getG());
        DHPrivateKeySpec AprivSpec = new DHPrivateKeySpec(da, dhSpec.getP(), dhSpec.getG());

        KeyPair A = new KeyPair(dhKeyFact.generatePublic(ApubSpec), dhKeyFact.generatePrivate(AprivSpec));

        // B's key pair
        BigInteger db = new BigInteger(adb, 16);
        BigInteger yb = G.modPow(db, P);
        System.out.println(yb.toString(16));

        DHPublicKeySpec BpubSpec = new DHPublicKeySpec(yb, dhSpec.getP(), dhSpec.getG());
        DHPrivateKeySpec BprivSpec = new DHPrivateKeySpec(db, dhSpec.getP(), dhSpec.getG());

        KeyPair B = new KeyPair(dhKeyFact.generatePublic(BpubSpec), dhKeyFact.generatePrivate(BprivSpec));

        // Key exchange
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
        aKeyAgree.init(A.getPrivate());
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");
        bKeyAgree.init(B.getPrivate());

        aKeyAgree.doPhase(B.getPublic(), true);
        bKeyAgree.doPhase(A.getPublic(), true);

        byte[] aSecret = aKeyAgree.generateSecret();
        byte[] bSecret = bKeyAgree.generateSecret();

        if (!Arrays.equals(aSecret, bSecret))
        {
            Util.handleError("Shared secret are not the same.");
        }

        return aSecret;

    }

    public static byte[] digestMessage(byte[] plainBytes, String shaMode)
    {
        ExtendedDigest messageDigest = null;

        if (shaMode.equals("SHA1"))
        {
            messageDigest = new SHA1Digest();
        }
        else if (shaMode.equals("SHA224"))
        {
            messageDigest = new SHA224Digest();
        }
        else if (shaMode.equals("SHA256"))
        {
            messageDigest = new SHA256Digest();
        }
        else if (shaMode.equals("SHA384"))
        {
            messageDigest = new SHA384Digest();
        }
        else if (shaMode.equals("SHA512"))
        {
            messageDigest = new SHA512Digest();
        }
        else {
            Util.handleError("Unknown hash name.");
        }

    	messageDigest.update(plainBytes, 0, plainBytes.length);
    	byte[] sha = new byte[messageDigest.getDigestSize()];
    	messageDigest.doFinal(sha,0);
    	return sha;
    }

    /* Arguments in order :
        - p : The group's prime modulus in hexadecimal form
        - g : The group's generator in hexadecimal form
        - da : A's private value in hexadecimal form
        - db : B's private value in hexadecimal form
        - hash name : The name of the hash function to use to derive sk
    */
    public static void main(String[] args)
    {

        if (args.length != 5) {
            Util.handleError("Invalid argument number.");
        }

        try {
            byte[] secret = exchange(args[0], args[1], args[2], args[3]);
            System.out.println(Util.stoh(secret));

            if (!args[4].equals("")) {
                System.out.println(Util.stoh(digestMessage(secret, args[4])));
            }
        }
        catch (Exception e) {
            System.err.println(e);
            Util.handleError("An exception has occured.");
        }

    }
}