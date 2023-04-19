// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019


public class Blockcipher
{

	/* Arguments in order :
        - message : The message to encrypt/decrypt in hexadecimal
        - key : The key of the bloc cipher in hexadecimal
        - iv : The IV of the bloc cipher in hexadecimal
        - cipher : The name of the cipher to use
        - E/D : "E" for encryption, "D" for decryption
        - MCT : "MCT" if an MCT test is required, empty otherwise
    */
    public static void main(String[] args)
    {

        if (args.length != 6) {
            Util.handleError("Invalid argument number.");
        }

        byte[] message = Util.htos(args[0]);
        byte[] key = Util.htos(args[1]);
        byte[] iv = Util.htos(args[2]);
        String ciphername = args[3];
        boolean operation = true;
        String mct = args[5];

        if (args[4].equals("E")) {
            operation = true;
        }
        else if (args[4].equals("D")) {
            operation = false;
        }
        else {
            Util.handleError("Invalid operation");
        }

        try {
            byte[] output;

            if (mct.equals("MCT")) {
                output = processMCT(message, iv, key, ciphername, operation);
            }
            else {
                output = process(message, iv, key, ciphername, operation);
            }

            System.out.println(Util.stoh(output));
        }
        catch (Exception e) {
            System.err.println(e);
            Util.handleError("An exception has occured.");
        }
    }

    private static byte[] process(byte[] plainBytes,byte[] iv,byte[] key, String ciphername, boolean operation) throws Exception
    {
        // TODO: Encrypt or decrypt with given cipher
    }

    private static byte[] processMCT(byte[] plainBytes,byte[] iv,byte[] key, String ciphername, boolean operation) throws Exception
    {
        // ECB mode
        if (getMode(ciphername).equals("ECB")) {
            int plen = plainBytes.length;
            byte[] CT = new byte[plen];
            byte[] PT = new byte[plen];

            System.arraycopy(plainBytes, 0, PT, 0, plen);

            for (int i = 0; i < 1000; i++) {
                CT = process(PT, iv, key, ciphername, operation);
                System.arraycopy(CT, 0, PT, 0, plen);
            }

            return CT;
        }
        // OFB
        else if (getMode(ciphername).equals("OFB")) {
            int plen = plainBytes.length;
            byte[] CT = new byte[plen];
            byte[] PT = new byte[plen];
            byte[] IV = new byte[plen];
            byte[] lastCT = new byte[plen];
            byte[] tmp = new byte[plen];

            System.arraycopy(plainBytes, 0, PT, 0, plen);
            System.arraycopy(iv, 0, IV, 0, plen);

            for (int i = 0; i < 1000; i++) {
                CT = process(PT, IV, key, ciphername, operation);
                tmp = xor(CT, PT);

                if (i == 0) {
                    System.arraycopy(IV, 0, PT, 0, plen);
                }
                else {
                    System.arraycopy(lastCT, 0, PT, 0, plen);
                }
                System.arraycopy(tmp, 0, IV, 0, plen);
                System.arraycopy(CT, 0, lastCT, 0, plen);
            }

            return CT;
        }
        // CFB8 mode
        else if (getMode(ciphername).equals("CFB8")) {
            int plen = plainBytes.length;
            byte[] CT = new byte[plen];
            byte[] PT = new byte[plen];
            byte[] IV = new byte[16];
            byte[] cipher = new byte[16];
            byte[] tmp = new byte[plen];

            System.arraycopy(plainBytes, 0, PT, 0, plen);
            System.arraycopy(plainBytes, 0, CT, 0, plen);
            System.arraycopy(iv, 0, IV, 0, 16);

            for (int i = 0; i < 1000; i++) {

                // encryption
                if (operation) {
                    CT = process(PT, IV, key, ciphername, operation);
                    System.arraycopy(IV, 0, PT, 0, 1);
                    System.arraycopy(IV, 1, IV, 0, 15);
                    System.arraycopy(CT, 0, IV, 15, 1);
                }
                // decryption
                else {
                    PT = process(CT, IV, key, ciphername, operation);
                    System.arraycopy(CT, 0, tmp, 0, plen);
                    if (i < 16) {
                        System.arraycopy(IV, 0, CT, 0, 1);
                        System.arraycopy(PT, 0, cipher, i, 1);
                    }
                    else {
                        System.arraycopy(cipher, 0, CT, 0, 1);
                        System.arraycopy(cipher, 1, cipher, 0, 15);
                        System.arraycopy(PT, 0, cipher, 15, 1);
                    }
                    System.arraycopy(IV, 1, IV, 0, 15);
                    System.arraycopy(tmp, 0, IV, 15, 1);
                }
            }

            // encryption
            if (operation) {
                return CT;
            }
            return PT;
        }
        // CBC, CFB
        else {
            int plen = plainBytes.length;
            byte[] CT = new byte[plen];
            byte[] PT = new byte[plen];
            byte[] IV = new byte[plen];
            byte[] lastCT = new byte[plen];
            byte[] tmp = new byte[plen];

            System.arraycopy(plainBytes, 0, PT, 0, plen);
            System.arraycopy(plainBytes, 0, CT, 0, plen);
            System.arraycopy(iv, 0, IV, 0, plen);

            for (int i = 0; i < 1000; i++) {

                // encryption
                if (operation) {
                    CT = process(PT, IV, key, ciphername, operation);
                    if (i == 0) {
                        System.arraycopy(IV, 0, PT, 0, plen);
                    }
                    else {
                        System.arraycopy(lastCT, 0, PT, 0, plen);
                    }

                    System.arraycopy(CT, 0, IV, 0, plen);
                    System.arraycopy(CT, 0, lastCT, 0, plen);
                }
                // decryption
                else {
                    PT = process(CT, IV, key, ciphername, operation);
                    System.arraycopy(IV, 0, tmp, 0, plen);
                    System.arraycopy(CT, 0, IV, 0, plen);

                    if (i == 0) {
                        System.arraycopy(tmp, 0, CT, 0, plen);
                    }
                    else {
                        System.arraycopy(lastCT, 0, CT, 0, plen);
                    }
                    System.arraycopy(PT, 0, lastCT, 0, plen);
                }

            }
            // encryption
            if (operation) {
                return CT;
            }
            return PT;
        }
    }

    public static byte[] xor(byte[] array_1, byte[] array_2) {
        byte[] array_3 = new byte[array_1.length];
        int i = 0;
        for (int b : array_1)
            array_3[i] = (byte)(b ^ (int) array_2[i++]);
        return array_3;
    }

    public static String getMode(String name) {
        return name.split("-")[2];
    }

    public static BufferedBlockCipher chooseCipher(String name)
    {
    	BufferedBlockCipher cipher = null;

        // TODO: Instanciate the proper cipher from the name

        return cipher;
    }
}