package ChameleonHash.CH.BaseCH.DKS_2020;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.CH.BaseCH.Components.HashValue<HashValue> {
    protected MultivePoint O;

    @Override
    public final boolean isEqual(HashValue other) {
        return O.isEqual(other.O);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

