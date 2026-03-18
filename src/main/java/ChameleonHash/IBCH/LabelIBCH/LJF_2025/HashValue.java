package ChameleonHash.IBCH.LabelIBCH.LJF_2025;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.IBCH.LabelIBCH.Components.HashValue<HashValue> {
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
