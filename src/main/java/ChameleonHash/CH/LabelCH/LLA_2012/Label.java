package ChameleonHash.CH.LabelCH.LLA_2012;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class Label extends ChameleonHash.CH.LabelCH.Components.Label {
    protected MultivePoint L, R;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
