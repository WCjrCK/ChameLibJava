package Encryption.SE.AES;

import utils.ElementCounter;

public class SecretKey extends Encryption.Components.SecretKey {
    byte[] key;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
