package Encryption.ABE.MAABE.RW_2015;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class PublicKey extends Encryption.ABE.MAABE.Components.PublicKey {
    MultivePoint egg_alpha, g_y;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
