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


public class ECDH
{
    public static byte[] exchange(String curveName, String ada, String axb, String ayb) throws Exception {


        //TODO: A's key pair

        // TODO: print A's coordinates (x, y) in hex :
        //System.out.println(xa.toString(16));
        //System.out.println(ya.toString(16));


        // B's key pair

        //TODO: Key exchange


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