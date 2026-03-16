package Encryption.ABE.FAME;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class PlainText extends Encryption.ABE.Components.PlainText<PlainText> {
    public MultivePoint m;

    @Override
    public final boolean isEqual(PlainText o) {
        return m.isEqual(o.m);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }

    public final String toString() {
        return "m = " + m.toString();
    }
}
