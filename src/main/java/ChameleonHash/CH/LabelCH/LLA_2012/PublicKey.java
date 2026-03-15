package ChameleonHash.CH.LabelCH.LLA_2012;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class PublicKey extends ChameleonHash.CH.Components.PublicKey {
    protected MultivePoint g, y_1, y_2, omega_1;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
