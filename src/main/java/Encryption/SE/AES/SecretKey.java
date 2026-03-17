package Encryption.SE.AES;

import utils.ElementCounter;

public class SecretKey extends Encryption.SE.Components.SecretKey {
    byte[] key;

    SecretKey() {}

    SecretKey(byte[] sk) {
        key = sk;
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
