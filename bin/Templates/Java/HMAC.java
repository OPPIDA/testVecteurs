// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019

public class HMAC
{
    public HMAC(String shaMode)
    {
    	// constructor
    }

    public byte[] doDigest(byte[] plainBytes)
    {
    	// Compute a hash
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

        System.out.println(Util.stoh(hmac.doDigest(Util.htos(args[1]))));
    }
}