package ChameleonHash.CH.CHET.KOG_CDK_2017;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class SecretKey extends ChameleonHash.CH.Components.SecretKey {
    protected Scalar x;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

