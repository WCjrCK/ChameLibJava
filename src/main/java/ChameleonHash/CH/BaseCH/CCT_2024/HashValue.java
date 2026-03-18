package ChameleonHash.CH.BaseCH.CCT_2024;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.CH.BaseCH.Components.HashValue<HashValue> {
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

