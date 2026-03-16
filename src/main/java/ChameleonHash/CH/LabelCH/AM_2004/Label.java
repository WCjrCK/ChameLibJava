package ChameleonHash.CH.LabelCH.AM_2004;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Label extends ChameleonHash.CH.LabelCH.Components.Label {
    protected Scalar L;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
