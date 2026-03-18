package ChameleonHash.PBCH.BAPBCH.TLL_2020;

import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import utils.ElementCounter;

import java.util.Arrays;
import java.util.Map;

public class SecretKey extends ChameleonHash.PBCH.BasePBCH.Components.SecretKey {
    protected Encryption.ABE.BaseABE.FAME.SecretKey FAME_sk;
    public MultivePoint[] sk_0_g;
    public MultivePoint sk_1;
    public Scalar sk_ch;
    public MultivePoint[] sk_2;
    Scalar delegate_z;

    public void CopyFrom(SecretKey o) {
        FAME_sk.CopyFrom(o.FAME_sk);
        sk_0_g = Arrays.copyOf(o.sk_0_g, o.sk_0_g.length);
        sk_2 = Arrays.copyOf(o.sk_2, o.sk_2.length);
        sk_1 = o.sk_1;
        sk_ch = o.sk_ch;
    }

    public boolean delegate(PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, MultivePoint ID_i_1, Scalar I_i_1) {
//            mod.ssk.sk_FAME, SP.pp_FAME, mpk.mpk_FAME, msk.msk_FAME, S, r_1, r_2, R
        if(sk_2.length == 0) return false;
        Scalar z_1 = pp.curve.getRandomScalar();
        Scalar z_2 = pp.curve.getRandomScalar();
        Scalar z = z_1.add(z_2);
        delegate_z = delegate_z.add(z);

        Scalar b1z1a1 = msk.FAME_msk.b_1.mul(z_1);
        Scalar b2z2a1 = msk.FAME_msk.b_2.mul(z_2);

        FAME_sk.sk_0[0] = FAME_sk.sk_0[0].mul(mpk.FAME_mpk.h.pow(b1z1a1));
        Scalar b1z1a2 = b1z1a1.div(msk.FAME_msk.a_2);
        b1z1a1 = b1z1a1.div(msk.FAME_msk.a_1);
        FAME_sk.sk_0[1] = FAME_sk.sk_0[1].mul(mpk.FAME_mpk.h.pow(b2z2a1));
        Scalar b2z2a2 = b2z2a1.div(msk.FAME_msk.a_2);
        b2z2a1 = b2z2a1.div(msk.FAME_msk.a_1);
        FAME_sk.sk_0[2] = FAME_sk.sk_0[2].mul(mpk.h_1_alpha.pow(z));
        sk_0_g[1] = sk_0_g[1].mul(sk_0_g[0].pow(z));

        Scalar alpha_a_1 = msk.alpha.mul(msk.FAME_msk.a_1);
        Scalar alpha_a_2 = msk.alpha.mul(msk.FAME_msk.a_2);
        Scalar zaa1 = z.div(alpha_a_1);
        Scalar zaa2 = z.div(alpha_a_2);

        for(Map.Entry<String, Integer> entry : FAME_sk.Attr2id.entrySet()) {
            FAME_sk.sk_y[entry.getValue()][0] = FAME_sk.sk_y[entry.getValue()][0].mul(pp.FAME_pp.H(entry.getKey() + "11").pow(b1z1a1)
                    .mul(pp.FAME_pp.H(entry.getKey() + "21").pow(b2z2a1))
                    .mul(pp.FAME_pp.H(entry.getKey() + "31").pow(zaa1)));

            FAME_sk.sk_y[entry.getValue()][1] = FAME_sk.sk_y[entry.getValue()][1].mul(pp.FAME_pp.H(entry.getKey() + "12").pow(b1z1a2)
                    .mul(pp.FAME_pp.H(entry.getKey() + "22").pow(b2z2a2))
                    .mul(pp.FAME_pp.H(entry.getKey() + "32").pow(zaa2)));
        }
        FAME_sk.sk_p[0] = FAME_sk.sk_p[0].mul(pp.FAME_pp.H("0111").pow(b1z1a1)
                .mul(pp.FAME_pp.H("0121").pow(b2z2a1))
                .mul(pp.FAME_pp.H("0131").pow(zaa1)));

        FAME_sk.sk_p[1] = FAME_sk.sk_p[1].mul(pp.FAME_pp.H("0112").pow(b1z1a2)
                .mul(pp.FAME_pp.H("0122").pow(b2z2a2))
                .mul(pp.FAME_pp.H("0132").pow(zaa2)));

        sk_1 = sk_1.mul(sk_2[0].pow(I_i_1)).mul(ID_i_1.pow(z));
        sk_2 = Arrays.copyOfRange(sk_2, 1, sk_2.length);
        sk_2[0] = sk_2[0].mul(mpk.g_alpha_i[sk_2.length - 1].pow(delegate_z));

        return true;
    }

    @Override
    public final ElementCounter TheoSize() {
        ElementCounter res = new ElementCounter();
        res.count(this);
        return res;
    }
}
