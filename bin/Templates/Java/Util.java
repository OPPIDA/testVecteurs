// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019

public class Util
{
    public static byte[] htos(String hex)
    {
        int l = hex.length();
        byte[] data = new byte[l/2];
        for (int i = 0; i < l; i += 2) {
            data[i/2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
    
    public static String stoh(byte[] b)
    {
    	 int len = b.length;
    	 String data = new String();

    	 for (int i = 0; i < len; i++)
    	 {
    		 data += Integer.toHexString((b[i] >> 4) & 0xf);
    		 data += Integer.toHexString(b[i] & 0xf);
    	 }
    	 return data;
    }

    public static void handleError(String err) {
        System.err.println(err);
        System.exit(-1);
    }
}