package scheme.IBCH.ZSS_2003;

import EllipticCurve.Curve.CurveGroup;
import scheme.Config;
import scheme.IBCH.IBCH;

/*
 * ID-Based Chameleon Hashes from Bilinear Pairings
 * P4. 4.2 Scheme 2
 */

public class S2 extends IBCH<PublicParam, MasterSecretKey, SecretKey, Identity, Message, HashValue, Randomness> {
    @Override
    public final PublicParam createPublicParam(Config config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(
            PublicParam pp,
            MasterSecretKey msk
    ) {
        msk.s = pp.curve.getRandomScalar();
        pp.P = pp.curve.getRandomPoint(CurveGroup.G1);
        pp.P_pub = pp.P.mul(msk.s);
    }

    @Override
    public void KeyGen(
            SecretKey sk,
            PublicParam pp,
            MasterSecretKey msk,
            Identity ID
    ) {
        sk.S_ID = pp.P.div(msk.s.add(pp.H1(ID.ID)));
    }

    public void CalHash(HashValue h, PublicParam pp, Identity ID, Message m, Randomness r) {
        h.h = pp.curve.Pairing(pp.P, pp.P).mul(pp.curve.Pairing(pp.P_pub.add(pp.P.mul(pp.H1(ID.ID))), r.R)).pow(pp.H1(m.m));
    }

    @Override
    public void Hash(
            HashValue h,
            Randomness r,
            PublicParam pp,
            Identity ID,
            Message m
    ) {
        r.R = pp.curve.getRandomPoint(CurveGroup.G1);
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
        r_p.R = sk.S_ID.mul(pp.H1(m.m).sub(pp.H1(m_p.m))).add(r.R.mul(pp.H1(m.m))).div(pp.H1(m_p.m));
    }
}
