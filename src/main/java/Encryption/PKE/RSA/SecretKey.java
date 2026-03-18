package Encryption.PKE.RSA;

import utils.ElementCounter;

import java.math.BigInteger;

public class SecretKey extends Encryption.PKE.Components.SecretKey<SecretKey> {
    public BigInteger p, q, d;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    @Override
    public void CopyFrom(SecretKey o) {
        p = o.p;
        q = o.q;
        d = o.d;
    }
}
