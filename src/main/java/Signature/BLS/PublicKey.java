package Signature.BLS;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class PublicKey extends Signature.Components.PublicKey {
    MultivePoint h;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
