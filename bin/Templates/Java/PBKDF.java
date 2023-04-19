// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019


public class PBKDF
{
    public byte[] pbkdfHmac(byte[] password, byte[] salt, int iter, int resultLen, String shaMode)
    {
        // todo
        return 0;
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