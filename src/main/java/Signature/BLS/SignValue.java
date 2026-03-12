package Signature.BLS;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class SignValue extends Signature.Components.SignValue {
    MultivePoint sigma_m;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
