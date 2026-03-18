package Encryption.ABE.BaseABE.FAME;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class MasterPublicKey extends Encryption.ABE.BaseABE.Components.MasterPublicKey {
    public MultivePoint g;
    public MultivePoint h;
    protected MultivePoint H_1;
    protected MultivePoint H_2;
    protected MultivePoint T_1;
    protected MultivePoint T_2;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
