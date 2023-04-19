// Author : Florian Picca <florian.picca@oppida.fr>
// Date : January 2020

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class GCM
{
    /* Arguments in order :
        - message : The message to encrypt/decrypt in hexadecimal
        - key : The key of the bloc cipher in hexadecimal
        - iv : The IV of the bloc cipher in hexadecimal
        - header : The additional data in hexadecimal
        - tag : The tag in hexadecimal
        - E/D : "E" for encryption, "D" for decryption
    */
    public static void main(String[] args)
    {
        if (args.length != 6) {
            Util.handleError("Invalid argument number.");
        }

    	GCM gcm = new GCM();
        byte[] message = Util.htos(args[0]);
        byte[] key = Util.htos(args[1]);
        byte[] iv = Util.htos(args[2]);
        byte[] header = Util.htos(args[3]);
        byte[] tag = Util.htos(args[4]);
        String operation = args[5];

        if (operation.equals("E")) {
            try {
                AEADParameters p = gcm.createParams(key, iv, header, tag.length*8);
                byte[] ct = gcm.encrypt(message, header, p);
                System.out.println(Util.stoh(ct));
            }
            catch (InvalidCipherTextException e) {
                Util.handleError("Encryption failed");
            }

        }
        else if (operation.equals("D")) {
            try {
                AEADParameters p = gcm.createParams(key, iv, header, tag.length*8);
                byte[] ct = Util.htos(args[0]+args[4]);
                byte[] pt = gcm.decrypt(ct, header, p);
                if (pt.length == 0) {
                    System.out.println("good");
                }
                else {
                    System.out.println(Util.stoh(pt));
                }
            }
            catch (InvalidCipherTextException e) {
                // invalid MAC
                System.out.println("fail");
            }
        }
        else {
            Util.handleError("'E' or 'D' expected");
        }
    }

    private AEADParameters createParams(byte[] keybytes,byte[] nouncebytes,byte[] associatedText, int tag_len)
    {
        KeyParameter key = new KeyParameter(keybytes);
        AEADParameters params = new AEADParameters(key, tag_len, nouncebytes, associatedText);
        return params;
    }

    /** Returns the ciphertext encrypted from the given plaintext and AEAD parameters.
     * @throws InvalidCipherTextException
     * @throws IllegalStateException */
    private byte[] encrypt(byte[] plaintext,byte[] AAD, AEADParameters params)throws InvalidCipherTextException
    {
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
        gcm.init(true, params);
        int outsize = gcm.getOutputSize(plaintext.length);
        byte[] out = new byte[outsize];
        int offOut = gcm.processBytes(plaintext, 0, plaintext.length, out, 0);
        gcm.doFinal(out, offOut);
        return out;
    }

    /** Returns the plaintext decrypted from the given ciphertext and AEAD parameters. */
    private byte[] decrypt(byte[] ciphertext,byte[] AAD, AEADParameters params) throws InvalidCipherTextException
    {
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
        gcm.init(false, params);
        int outsize = gcm.getOutputSize(ciphertext.length);
        byte[] out = new byte[outsize];
        int offOut = gcm.processBytes(ciphertext, 0, ciphertext.length, out, 0);
        gcm.doFinal(out, offOut);
        return out;
    }
}