package ChameleonHash.CH.LabelCH.LLA_2012;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class SecretKey extends ChameleonHash.CH.Components.SecretKey {
    protected Scalar alpha, x_1, x_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
