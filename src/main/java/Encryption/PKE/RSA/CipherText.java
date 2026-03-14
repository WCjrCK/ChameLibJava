package Encryption.PKE.RSA;

import utils.ElementCounter;

import java.math.BigInteger;

public class CipherText extends Encryption.Components.CipherText<CipherText> {
    public BigInteger ct;
    @Override
    public final boolean isEqual(CipherText o) {
        return ct.equals(o.ct);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
