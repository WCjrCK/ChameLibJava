package ChameleonHash.CH.CHET.KOG_CDK_2017;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class PublicKey extends ChameleonHash.CH.Components.PublicKey {
    protected MultivePoint g_x;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

