package ChameleonHash.IBCH.BaseIBCH.ZSS_2003;

import ChameleonHash.IBCH.IBCHConfig;
import ChameleonHash.Interface.BaseIBCH;
import EllipticCurve.Curve.CurveGroup;

/*
 * ID-Based Chameleon Hashes from Bilinear Pairings
 * P4. 4.1 Scheme 1
 */

public class S1
        extends ChameleonHash.IBCH.BaseIBCH.Scheme<PublicParam, MasterSecretKey, SecretKey, Identity, Message, HashValue, Randomness>
        implements BaseIBCH<PublicParam, MasterSecretKey, SecretKey, Identity, Message, HashValue, Randomness> {
    @Override
    public final PublicParam createPublicParam(IBCHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(
            PublicParam pp,
            MasterSecretKey msk
    ) {
        msk.s = pp.curve.getRandomScalar();
        pp.P = pp.curve.getRandomPoint(CurveGroup.G2);
        pp.P_pub = pp.P.mul(msk.s);
    }

    @Override
    public void KeyGen(
            SecretKey sk,
            PublicParam pp,
            MasterSecretKey msk,
            Identity ID
    ) {
        sk.S_ID = pp.H0(ID.ID).mul(msk.s);
    }

    public void CalHash(HashValue h, PublicParam pp, Identity ID, Message m, Randomness r) {
        h.h = pp.curve.Pairing(r.R, pp.P).mul(pp.curve.Pairing(pp.H0(ID.ID).mul(pp.H1(m.m)), pp.P_pub));
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
    public void Collision (
            Randomness r_p,
            PublicParam pp,
            Identity ID,
            SecretKey sk,
            Message m,
            HashValue h,
            Randomness r,
            Message m_p
    ) {
        r_p.R = sk.S_ID.mul(pp.H1(m.m).sub(pp.H1(m_p.m))).add(r.R);
    }
}
