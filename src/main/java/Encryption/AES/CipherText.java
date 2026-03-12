package Encryption.AES;

import utils.ElementCounter;

import java.util.Arrays;

public class CipherText extends Encryption.Components.CipherText {
    public byte[] ct;
    @Override
    public final boolean isEqual(Encryption.Components.CipherText o) {
        if(o instanceof CipherText) return Arrays.equals(ct, ((CipherText) o).ct);
        return false;
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
