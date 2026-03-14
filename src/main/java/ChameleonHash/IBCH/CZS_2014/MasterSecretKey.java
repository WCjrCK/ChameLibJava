package ChameleonHash.IBCH.CZS_2014;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class MasterSecretKey extends ChameleonHash.IBCH.Components.MasterSecretKey {
    protected Scalar x;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
