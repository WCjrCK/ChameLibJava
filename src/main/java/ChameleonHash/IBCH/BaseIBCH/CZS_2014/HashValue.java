package ChameleonHash.IBCH.BaseIBCH.CZS_2014;

import EllipticCurve.Point.AdditivePoint;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.IBCH.BaseIBCH.Components.HashValue<HashValue> {
    protected AdditivePoint h;

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
