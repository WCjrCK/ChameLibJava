package Encryption.AES;

import utils.ElementCounter;

import java.util.Random;

public class SecretKey extends Encryption.Components.SecretKey {
    byte[] key;

    SecretKey() {
        key = new byte[32];
        Random rand = new Random();
        rand.nextBytes(key);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
