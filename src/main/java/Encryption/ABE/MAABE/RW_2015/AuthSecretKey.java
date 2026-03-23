package Encryption.ABE.MAABE.RW_2015;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class AuthSecretKey extends Encryption.ABE.MAABE.Components.AuthSecretKey {
    Scalar alpha, y;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
