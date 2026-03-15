package ChameleonHash.IBCH.BaseIBCH.XSL_2021;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class Randomness extends ChameleonHash.IBCH.Components.Randomness {
    protected MultivePoint r_1, r_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
