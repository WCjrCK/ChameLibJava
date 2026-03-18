package ChameleonHash.CH.LabelCH.CZT_2011;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class PublicKey extends ChameleonHash.CH.LabelCH.Components.PublicKey {
    protected MultivePoint y;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

