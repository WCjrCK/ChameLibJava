package Encryption.AE.RSA;

import utils.ElementCounter;

import java.math.BigInteger;

public class PublicKey extends Encryption.AE.Components.PublicKey {
    public BigInteger N, e;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
