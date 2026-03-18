package ChameleonHash.CH.LabelCH.LLA_2012;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class HashValue extends ChameleonHash.CH.LabelCH.Components.HashValue<HashValue> {
    protected MultivePoint S;

    @Override
    public final boolean isEqual(HashValue other) {
        return S.isEqual(other.S);
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
