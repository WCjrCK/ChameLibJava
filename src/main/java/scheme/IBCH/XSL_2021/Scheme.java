package scheme.IBCH.XSL_2021;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.MultivePoint;
import scheme.Config;
import scheme.IBCH.IBCH;

/*
 * Identity-Based Chameleon Hash without Random Oracles and Application in the Mobile Internet
 * P4. V. CONSTRUCTION
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
        AdditivePoint alpha = pp.curve.createPoint(CurveGroup.Zp);
        pp.g = pp.curve.createPoint(CurveGroup.G1);
        pp.g_1 = pp.g.pow(alpha);

        pp.g_2 = pp.curve.createPoint(CurveGroup.G2);
        for(int i = 0;i <= pp.n;++i) pp.u[i] = pp.curve.createPoint(CurveGroup.G2);
        msk.g_2_alpha = pp.g_2.pow(alpha);
    }

    private MultivePoint getIDItem(PublicParam pp, Identity ID) {
        MultivePoint res = pp.u[0].copy();
        for(int i = 1;i <= pp.n;++i) {
            if(ID.I.get(i - 1)) res = res.mul(pp.u[i]);
        }
        return res;
    }

    @Override
    public void KeyGen(
            SecretKey sk,
            PublicParam pp,
            MasterSecretKey msk,
            Identity ID
    ) {
        AdditivePoint t = pp.curve.createPoint(CurveGroup.Zp);
        sk.tk_1 = msk.g_2_alpha.mul(getIDItem(pp, ID).pow(t));
        sk.tk_2 = pp.g.pow(t);
    }

    public void CalHash(HashValue h, PublicParam pp, Identity ID, Message m, Randomness r) {
        h.h = pp.curve.Pairing(pp.g_1, pp.g_2).pow(m.m).mul(pp.curve.Pairing(pp.g, r.r_1).div(pp.curve.Pairing(r.r_2, getIDItem(pp, ID))));
    }

    @Override
    public void Hash(
            HashValue h,
            Randomness r,
            PublicParam pp,
            Identity ID,
            Message m
    ) {
        r.r_1 = pp.curve.createPoint(CurveGroup.G2);
        r.r_2 = pp.curve.createPoint(CurveGroup.G1);
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
    ) {        AdditivePoint delta_m = m.m.sub(m_p.m);
        r_p.r_1 = r.r_1.mul(sk.tk_1.pow(delta_m));
        r_p.r_2 = r.r_2.mul(sk.tk_2.pow(delta_m));
    }
}
