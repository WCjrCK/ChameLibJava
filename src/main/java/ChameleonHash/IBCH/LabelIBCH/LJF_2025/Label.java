package ChameleonHash.IBCH.LabelIBCH.LJF_2025;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Label extends ChameleonHash.IBCH.LabelIBCH.Components.Label {
    protected Scalar L;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
