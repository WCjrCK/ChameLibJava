package ChameleonHash.IBCH.LabelIBCH.LJF_2025;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class Randomness extends ChameleonHash.IBCH.Components.Randomness {
    protected Scalar r_1;
    protected MultivePoint r_2, r_3;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
