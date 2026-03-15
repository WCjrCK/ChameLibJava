package ChameleonHash.IBCH.LabelIBCH.LJF_2025;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class MasterSecretKey extends ChameleonHash.IBCH.Components.MasterSecretKey {
    protected Scalar alpha, beta;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
