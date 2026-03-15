package Encryption.ABE.FAME;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class MasterPublicKey extends Encryption.ABE.Components.MasterPublicKey {
    protected MultivePoint g, h, H_1, H_2, T_1, T_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
