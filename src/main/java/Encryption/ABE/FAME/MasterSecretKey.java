package Encryption.ABE.FAME;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class MasterSecretKey extends Encryption.ABE.Components.MasterSecretKey {
    protected MultivePoint g_d1, g_d2, g_d3;
    Scalar a_1, a_2, b_1, b_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
