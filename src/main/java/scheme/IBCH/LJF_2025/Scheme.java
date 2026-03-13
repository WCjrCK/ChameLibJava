package scheme.IBCH.LJF_2025;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import scheme.Config;
import scheme.IBCH.IBCH;

/*
 * Identity-Based Chameleon Hashes in the Standard Model for Mobile Devices
 * P6. V. PROPOSED IB-CH SCHEME WITHOUT KEY EXPOSURE
 */

public class Scheme extends IBCH<PublicParam, MasterSecretKey, SecretKey, Identity, Message, HashValue, Randomness> {
    @Override
    public final PublicParam createPublicParam(Config config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(
            PublicParam pp,
            MasterSecretKey msk
    ) {
        msk.alpha = pp.curve.createPoint(CurveGroup.Zp);
        msk.beta = pp.curve.createPoint(CurveGroup.Zp);
        pp.g = pp.curve.createPoint(CurveGroup.G1);
        pp.g_1 = pp.g.pow(msk.alpha);
        pp.g_2 = pp.g.pow(msk.beta);
        pp.h_2 = pp.curve.createPoint(CurveGroup.G1);
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
        sk.td_1 = pp.curve.createPoint(CurveGroup.Zp);
        sk.td_2 = pp.g.pow(msk.beta.sub(sk.td_1).mulZn(msk.alpha.sub(ID.ID).invZn()));
    }

    public void CalHash(HashValue h, PublicParam pp, Identity ID, Message m, Randomness r) {
        h.h = pp.eg_2g.pow(m.m).mul(pp.egg.pow(r.r_1)).mul(pp.curve.Pairing(r.r_2, pp.g_1.mul(pp.g.pow(ID.ID.neg())))).mul(pp.curve.Pairing(pp.u_2.mul(pp.h_2.pow(ID.ID.neg())).pow(ID.L), r.r_3));
    }

    @Override
    public void Hash(
            HashValue h,
            Randomness r,
            PublicParam pp,
            Identity ID,
            Message m
    ) {
        r.r_1 = pp.curve.createPoint(CurveGroup.Zp);
        r.r_2 = pp.curve.createPoint(CurveGroup.G1);
        r.r_3 = pp.curve.createPoint(CurveGroup.G1);
        CalHash(h, pp, ID, m, r);
    }

    @Override
    public boolean Verify(
            PublicParam pp,
            Identity ID,
            Message m,
            HashValue h,
            Randomness r
    ) {
        HashValue tmp = new HashValue();
        CalHash(tmp, pp, ID, m, r);
        return tmp.isEqual(h);
    }

    @Override
    public void Collision(
            Randomness r_p,
            PublicParam pp,
            Identity ID,
            SecretKey sk,
            Message m,
            HashValue h,
            Randomness r,
            Message m_p
    ) {
        AdditivePoint t_p = pp.curve.createPoint(CurveGroup.Zp);
        MultivePoint td_2 = sk.td_2.mul(pp.u_2.mul(pp.h_2.pow(ID.ID.neg())).pow(ID.L.mulZn(t_p)));
        MultivePoint td_3 = pp.g_1.mul(pp.g.pow(ID.ID.neg())).pow(t_p);
        AdditivePoint delta_m = m.m.sub(m_p.m);
        r_p.r_1 = r.r_1.add(sk.td_1.mulZn(delta_m));
        r_p.r_2 = r.r_2.mul(td_2.pow(delta_m));
        r_p.r_3 = r.r_3.mul(td_3.pow(delta_m.neg()));
    }
}
