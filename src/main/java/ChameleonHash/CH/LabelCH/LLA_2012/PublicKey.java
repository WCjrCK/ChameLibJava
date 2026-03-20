package ChameleonHash.CH.LabelCH.LLA_2012;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class PublicKey extends ChameleonHash.CH.LabelCH.Components.PublicKey {
    protected MultivePoint y_1, y_2, omega_1;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
