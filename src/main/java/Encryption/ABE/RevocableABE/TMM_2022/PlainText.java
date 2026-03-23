package Encryption.ABE.RevocableABE.TMM_2022;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class PlainText extends Encryption.ABE.RevocableABE.Components.PlainText<PlainText> {
    public Scalar m;

    public boolean isEqual(PlainText o) {
        return m.isEqual(o.m);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
