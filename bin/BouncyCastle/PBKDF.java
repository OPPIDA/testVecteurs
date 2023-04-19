// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;


public class PBKDF
{
    public byte[] pbkdfHmac(byte[] password, byte[] salt, int iter, int resultLen, String shaMode)
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

        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(messageDigest);
        gen.init(password, salt, iter);
        byte[] dk = ((KeyParameter) gen.generateDerivedParameters(resultLen * 8)).getKey();
        return dk;
    }

    /* Arguments in order :
        - password : The password in hexadecimal
        - salt : The salt in hexadecimal
        - iterations : The number of iterations
        - dklen : The output key length
        - hash name : The name of the hash function to use to derive sk
    */
    public static void main(String[] args)
    {
        if (args.length != 5) {
            Util.handleError("Invalid argument number.");
        }
        PBKDF pb = new PBKDF();

        System.out.println(Util.stoh(pb.pbkdfHmac(Util.htos(args[0]), Util.htos(args[1]), Integer.parseInt(args[2]), Integer.parseInt(args[3]), args[4])));

    }
}