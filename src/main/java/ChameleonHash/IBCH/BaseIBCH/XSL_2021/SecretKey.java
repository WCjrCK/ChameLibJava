package ChameleonHash.IBCH.BaseIBCH.XSL_2021;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class SecretKey extends ChameleonHash.IBCH.BaseIBCH.Components.SecretKey {
    protected MultivePoint tk_1, tk_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
