package ChameleonHash.CH.BaseCH.DKS_2020;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class PublicKey extends ChameleonHash.CH.Components.PublicKey {
    protected MultivePoint y;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}

