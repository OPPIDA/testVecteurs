// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019


public class DH
{
    public static byte[] exchange(String p, String g, String ada, String adb) throws Exception {


        // TODO: A's key pair

        // TODO: print A's y coordinate in hexadecimal
        //System.out.println(ya.toString(16));


        // TODO: B's key pair

        // TODO: print B's y coordinate in hexadecimal
        //System.out.println(yb.toString(16));


        // TODO: Key exchange


        if (!Arrays.equals(aSecret, bSecret))
        {
            Util.handleError("Shared secret are not the same.");
        }

        return aSecret;

    }

    public static byte[] digestMessage(byte[] plainBytes, String shaMode)
    {
        // compute hash
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