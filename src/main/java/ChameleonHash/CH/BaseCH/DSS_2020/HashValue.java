package ChameleonHash.CH.BaseCH.DSS_2020;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.CH.Components.HashValue<HashValue> {
    protected MultivePoint c_1, c_2;

    @Override
    public final boolean isEqual(HashValue other) {
        return c_1.isEqual(other.c_1) && c_2.isEqual(other.c_2);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

