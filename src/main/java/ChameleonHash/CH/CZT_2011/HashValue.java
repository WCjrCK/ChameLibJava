package ChameleonHash.CH.CZT_2011;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.CH.Components.HashValue<HashValue> {
    protected MultivePoint h;

    @Override
    public final boolean isEqual(HashValue other) {
        return h.isEqual(other.h);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

