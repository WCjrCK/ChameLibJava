package ChameleonHash.CH.LabelCH.CZK_2004;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class Label extends ChameleonHash.CH.LabelCH.Components.Label {
    protected MultivePoint I;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
