package Encryption.ABE.MAABE.RW_2015;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class PlainText extends Encryption.ABE.MAABE.Components.PlainText<PlainText> {
    public MultivePoint m;

    public boolean isEqual(PlainText o) {
        return m.isEqual(o.m);
    }

    @Override
    public byte[] toBytes() {
        return m.toBytes();
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
