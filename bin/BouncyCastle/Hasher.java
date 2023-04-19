// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;


public class Hasher
{
    public byte[] digestMessage(byte[] plainBytes, String shaMode)
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

    public void digestMessageMCT(byte[] plainBytes, String shaMode)
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

        // init the seed with 3x the message
        byte[][] seed = new byte[3][plainBytes.length];
        byte[] message = new byte[3*plainBytes.length];
        byte[] digest = new byte[messageDigest.getDigestSize()];
        digest = plainBytes;

        // 100 checkpoints
        for (int i = 0; i<100; i += 1) {

            // the seed is initialized with the last digest repeated 3 times
            System.arraycopy(digest, 0, seed[0], 0, plainBytes.length);
            System.arraycopy(digest, 0, seed[1], 0, plainBytes.length);
            System.arraycopy(digest, 0, seed[2], 0, plainBytes.length);

            // concat them to make the message to digest
            System.arraycopy(seed[0], 0, message, 0, plainBytes.length);
            System.arraycopy(seed[1], 0, message, plainBytes.length, plainBytes.length);
            System.arraycopy(seed[2], 0, message, 2*plainBytes.length, plainBytes.length);

            // checkpoint every 1000 iterations
            for (int j = 0; j<1000; j+=1) {
                // compute the hash of seed (3 strings in a row) and put it in digest
                messageDigest.update(message, 0, message.length);
    	        messageDigest.doFinal(digest,0);

                // rotate the seed
                System.arraycopy(seed[1], 0, seed[0], 0, plainBytes.length);
                System.arraycopy(seed[2], 0, seed[1], 0, plainBytes.length);
                System.arraycopy(digest, 0, seed[2], 0, plainBytes.length);

                // concat them to make the message to digest
                System.arraycopy(seed[0], 0, message, 0, plainBytes.length);
                System.arraycopy(seed[1], 0, message, plainBytes.length, plainBytes.length);
                System.arraycopy(seed[2], 0, message, 2*plainBytes.length, plainBytes.length);
            }

            // print the checkpoint
            System.out.println(Util.stoh(digest));
        }
    }

    /* Arguments in order :
        - message : hex string representing the message to hash
        - hash name : string representing the hash's name : SHA1, SHA224, SHA256, SHA384, SHA512 others are supported as well (MD5, SHA3-512, ...)
        - MCT : "MCT" if an MCT test is required, empty otherwise
    */
    public static void main(String[] args)
    {

        if (args.length != 3) {
            Util.handleError("Invalid argument number.");
        }

        Hasher hash = new Hasher();

        byte[] msg = Util.htos(args[0]);

        if (args[2].equals("MCT")) {
            hash.digestMessageMCT(msg, args[1]);
        }
        else {
            byte[] result = hash.digestMessage(msg, args[1]);
            String h = Util.stoh(result);
            System.out.println(h);
        }
    }
}