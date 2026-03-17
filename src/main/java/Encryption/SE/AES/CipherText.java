package Encryption.SE.AES;

import utils.ElementCounter;

import java.util.Arrays;

public class CipherText extends Encryption.SE.Components.CipherText<CipherText> {
    public byte[] ct;
    @Override
    public final boolean isEqual(CipherText o) {
        return Arrays.equals(ct, o.ct);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
