package Encryption.ABE.RevocableABE.TMM_2022;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class CipherText extends Encryption.ABE.Components.CipherText<CipherText> {
    protected Encryption.ABE.BaseABE.FAME.CipherText FAME_ct;
    MultivePoint ct_0_4;
    byte[] ct;

    public boolean isEqual(CipherText o) {
        return FAME_ct.isEqual(o.FAME_ct) && ct_0_4.isEqual(o.ct_0_4);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
