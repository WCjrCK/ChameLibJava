package ChameleonHash.PBCH.BAPBCH.TLL_2020;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.BaseABE.FAME.CipherText;
import utils.ElementCounter;

public class Randomness extends ChameleonHash.PBCH.Components.Randomness {
    protected CipherText FAME_ct;
    protected Scalar sigma;
    public MultivePoint epk, p, c, ct_0_4, ct_1, ct_2, ct_3;
    protected byte[] ct, ct_p;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
