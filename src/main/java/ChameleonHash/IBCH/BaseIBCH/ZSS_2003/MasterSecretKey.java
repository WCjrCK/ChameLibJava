package ChameleonHash.IBCH.BaseIBCH.ZSS_2003;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class MasterSecretKey extends ChameleonHash.IBCH.Components.MasterSecretKey {
    protected Scalar s;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
