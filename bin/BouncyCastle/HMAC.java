// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;


public class HMAC
{
    HMac hmac;
    public HMAC(String shaMode)
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

        hmac = new HMac(messageDigest);
    }

    public byte[] doDigest(byte[] plainBytes)
    {
    	hmac.update(plainBytes, 0, plainBytes.length);
    	byte[] mac = new byte[hmac.getMacSize()];
    	hmac.doFinal(mac,0);
    	return mac;
    }

    /* Arguments in order :
        - key : hex string representing the key
        - message : hex string representing the message to hash
        - hash name : string representing the hash's name : SHA1, SHA224, SHA256, SHA384, SHA512 others are supported as well (MD5, SHA3-512, ...)
    */
    public static void main(String[] args)
    {

        if (args.length != 3) {
            Util.handleError("Invalid argument number.");
        }


        HMAC hmac = new HMAC(args[2]);

        KeyParameter param = new KeyParameter(Util.htos(args[0]));

        hmac.hmac.init(param);
        System.out.println(Util.stoh(hmac.doDigest(Util.htos(args[1]))));
    }
}