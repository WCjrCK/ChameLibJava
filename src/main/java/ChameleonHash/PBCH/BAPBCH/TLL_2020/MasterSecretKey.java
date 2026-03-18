package ChameleonHash.PBCH.BAPBCH.TLL_2020;

import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

public class MasterSecretKey extends ChameleonHash.PBCH.BasePBCH.Components.MasterSecretKey {
    protected Encryption.ABE.BaseABE.FAME.MasterSecretKey FAME_msk;
    public Scalar alpha, beta, sk_ch;
    public Scalar[] z_i;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
