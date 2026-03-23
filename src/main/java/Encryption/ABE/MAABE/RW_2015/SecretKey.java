package Encryption.ABE.MAABE.RW_2015;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class SecretKey extends Encryption.ABE.MAABE.Components.SecretKey {
    MultivePoint K, K_p;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
