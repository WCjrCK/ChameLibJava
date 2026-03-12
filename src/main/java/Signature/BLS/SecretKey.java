package Signature.BLS;

import EllipticCurve.Point.AdditivePoint;
import utils.ElementCounter;

public class SecretKey extends Signature.Components.SecretKey {
    AdditivePoint alpha;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
