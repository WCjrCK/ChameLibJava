package ChameleonHash.CH.CHET.KOG_CDK_2017;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class ETrapdoor extends ChameleonHash.CH.CHET.Components.ETrapdoor {
    protected Scalar etd;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
