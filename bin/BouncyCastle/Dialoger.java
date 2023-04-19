// Author : Florian Picca <florian.picca@oppida.fr>
// Date : March 2020

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.Arrays;

public class Dialoger
{
    public static void main(String[] args)
    {
        try (BufferedReader buffReader = new BufferedReader(new InputStreamReader(System.in))) {

            String choice;
            String[] newArgs;
            //commands : QUIT VERSION PBKDF HMAC HASHER GCM ECDSA ECDH DH BLOCKCIPHER
            while (true) {
                choice = buffReader.readLine();
                if (choice.equals("QUIT")) {
                    break;
                }
                args = choice.split(",");
                newArgs = Arrays.copyOfRange(args, 1, args.length);

                for (int i=0; i<newArgs.length; i++) {
                    if (newArgs[i].equals("#")) {
                        newArgs[i] = "";
                    }
                }

                if (args[0].equals("GCM")) {
                    GCM.main(newArgs);
                }
                if (args[0].equals("HASHER")) {
                    Hasher.main(newArgs);
                }
                if (args[0].equals("BLOCKCIPHER")) {
                    Blockcipher.main(newArgs);
                }
                if (args[0].equals("DH")) {
                    DH.main(newArgs);
                }
                if (args[0].equals("ECDH")) {
                    ECDH.main(newArgs);
                }
                if (args[0].equals("HMAC")) {
                    HMAC.main(newArgs);
                }
                if (args[0].equals("PBKDF")) {
                    PBKDF.main(newArgs);
                }
                if (args[0].equals("VERSION")) {
                    Version.main(newArgs);
                }

                System.out.println(">");
            }
         }
         catch (IOException e) {
            System.err.print(e);
         }

    }
}