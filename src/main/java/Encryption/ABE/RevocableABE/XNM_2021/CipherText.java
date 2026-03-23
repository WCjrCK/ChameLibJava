package Encryption.ABE.RevocableABE.XNM_2021;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class CipherText extends Encryption.ABE.RevocableABE.Components.CipherText<CipherText, Policy> {
    protected Encryption.ABE.BaseABE.FAME.CipherText FAME_ct;
    MultivePoint ct_0_4;

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
