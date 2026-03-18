package Encryption.ABE.BaseABE.FAME;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class MasterSecretKey extends Encryption.ABE.Components.MasterSecretKey {
    public MultivePoint g_d1;
    public MultivePoint g_d2;
    public MultivePoint g_d3;
    public Scalar a_1;
    public Scalar a_2;
    public Scalar b_1;
    public Scalar b_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
