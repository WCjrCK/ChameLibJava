package ChameleonHash.IBCH.CZS_2014;

import EllipticCurve.Point.AdditivePoint;
import utils.ElementCounter;

public class SecretKey extends ChameleonHash.IBCH.Components.SecretKey {
    protected AdditivePoint S_ID;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
