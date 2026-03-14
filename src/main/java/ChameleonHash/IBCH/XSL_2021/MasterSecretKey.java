package ChameleonHash.IBCH.XSL_2021;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class MasterSecretKey extends ChameleonHash.IBCH.Components.MasterSecretKey {
    protected MultivePoint g_2_alpha;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
