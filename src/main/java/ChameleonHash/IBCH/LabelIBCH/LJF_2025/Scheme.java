package ChameleonHash.IBCH.LabelIBCH.LJF_2025;

import ChameleonHash.IBCH.IBCHConfig;
import ChameleonHash.Interface.LabelIBCH;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

/*
 * Identity-Based Chameleon Hashes in the Standard Model for Mobile Devices
 * P6. V. PROPOSED IB-CH SCHEME WITHOUT KEY EXPOSURE
 */

public class Scheme
        extends ChameleonHash.IBCH.LabelIBCH.Scheme<PublicParam, MasterSecretKey, SecretKey, Identity, Message, Label, HashValue, Randomness>
        implements LabelIBCH<PublicParam, MasterSecretKey, SecretKey, Identity, Message, Label, HashValue, Randomness> {
    @Override
    public final PublicParam createPublicParam(IBCHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(
            PublicParam pp,
            MasterSecretKey msk
    ) {
        msk.alpha = pp.curve.getRandomScalar();
        msk.beta = pp.curve.getRandomScalar();
        pp.g = pp.curve.getRandomPoint(CurveGroup.G1);
        pp.g_1 = pp.g.pow(msk.alpha);
        pp.g_2 = pp.g.pow(msk.beta);
        pp.h_2 = pp.curve.getRandomPoint(CurveGroup.G1);
        pp.u_2 = pp.h_2.pow(msk.alpha);
        pp.egg = pp.curve.Pairing(pp.g, pp.g);
        pp.eg_2g = pp.curve.Pairing(pp.g_2, pp.g);
    }

    @Override
    public void KeyGen(
            SecretKey sk,
            PublicParam pp,
            MasterSecretKey msk,
            Identity ID
    ) {
        sk.td_1 = pp.curve.getRandomScalar();
        sk.td_2 = pp.g.pow(msk.beta.sub(sk.td_1).div(msk.alpha.sub(ID.ID)));
    }

    public void CalHash(HashValue h, PublicParam pp, Identity ID, Message m, Label L, Randomness r) {
        h.h = pp.eg_2g.pow(m.m).mul(pp.egg.pow(r.r_1)).mul(pp.curve.Pairing(r.r_2, pp.g_1.div(pp.g.pow(ID.ID)))).mul(pp.curve.Pairing(pp.u_2.div(pp.h_2.pow(ID.ID)).pow(L.L), r.r_3));
    }

    @Override
    public void Hash(
            HashValue h,
            Randomness r,
            PublicParam pp,
            Identity ID,
            Message m, Label L
    ) {
        r.r_1 = pp.curve.getRandomScalar();
        r.r_2 = pp.curve.getRandomPoint(CurveGroup.G1);
        r.r_3 = pp.curve.getRandomPoint(CurveGroup.G1);
        CalHash(h, pp, ID, m, L, r);
    }

    @Override
    public boolean Verify(
            PublicParam pp,
            Identity ID,
            Message m,
            Label L,
            HashValue h,
            Randomness r
    ) {
        HashValue tmp = new HashValue();
        CalHash(tmp, pp, ID, m, L, r);
        return tmp.isEqual(h);
    }

    @Override
    public void Collision(
            Randomness r_p,
            PublicParam pp,
            Identity ID,
            SecretKey sk,
            Message m,
            Label L,
            HashValue h,
            Randomness r,
            Message m_p
    ) {
        Scalar t_p = pp.curve.getRandomScalar();
        MultivePoint td_2 = sk.td_2.mul(pp.u_2.div(pp.h_2.pow(ID.ID)).pow(L.L.mul(t_p)));
        MultivePoint td_3 = pp.g_1.div(pp.g.pow(ID.ID)).pow(t_p);
        Scalar delta_m = m.m.sub(m_p.m);
        r_p.r_1 = r.r_1.add(sk.td_1.mul(delta_m));
        r_p.r_2 = r.r_2.mul(td_2.pow(delta_m));
        r_p.r_3 = r.r_3.div(td_3.pow(delta_m));
    }
}
