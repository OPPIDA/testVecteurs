// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Version
{
    public static void main(String[] args)
    {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        System.out.println(bouncyCastleProvider.getVersionStr());
    }
}