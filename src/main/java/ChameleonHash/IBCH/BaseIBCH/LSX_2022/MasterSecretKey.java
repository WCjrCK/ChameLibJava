package ChameleonHash.IBCH.BaseIBCH.LSX_2022;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class MasterSecretKey extends ChameleonHash.IBCH.BaseIBCH.Components.MasterSecretKey {
    protected Scalar alpha, beta;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
