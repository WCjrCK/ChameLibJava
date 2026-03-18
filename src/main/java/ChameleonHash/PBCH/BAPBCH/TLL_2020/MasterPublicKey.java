package ChameleonHash.PBCH.BAPBCH.TLL_2020;

import EllipticCurve.Point.MultivePoint;
import utils.ElementCounter;

public class MasterPublicKey extends ChameleonHash.PBCH.Components.MasterPublicKey {
    protected Encryption.ABE.BaseABE.FAME.MasterPublicKey FAME_mpk;
    public MultivePoint g_alpha, h_d_alpha, h_1_alpha, h_beta_alpha, pk_ch;
    public MultivePoint[] g_i, g_alpha_i, h_i;

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
