package ChameleonHash.CH.LabelCH.AM_2004;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class SecretKey extends ChameleonHash.CH.LabelCH.Components.SecretKey {
    protected Scalar x;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
