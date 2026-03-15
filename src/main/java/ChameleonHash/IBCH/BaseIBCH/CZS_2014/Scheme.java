package ChameleonHash.IBCH.BaseIBCH.CZS_2014;

import ChameleonHash.IBCH.IBCHConfig;
import ChameleonHash.Interface.BaseIBCH;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.AdditivePoint;
import EllipticCurve.Point.Scalar;

/*
 * Identity-based chameleon hashing and signatures without key exposure
 * P6. 4.1. The proposed identity-based chameleon hash scheme
 */

public class Scheme
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
        msk.x = pp.curve.getRandomScalar();
        pp.P = pp.curve.getRandomPoint(CurveGroup.G1);
        pp.P_pub = pp.P.mul(msk.x);
    }

    @Override
    public void KeyGen(
            SecretKey sk,
            PublicParam pp,
            MasterSecretKey msk,
            Identity ID
    ) {
        sk.S_ID = pp.H_p(ID.L).mul(msk.x);
    }

    public void CalHash(HashValue h, PublicParam pp, Identity ID, Message m, Randomness r) {
        h.h = r.r_1.add(pp.H(ID.L).mul(m.m));
    }

    @Override
    public void Hash(
            HashValue h,
            Randomness r,
            PublicParam pp,
            Identity ID,
            Message m
    ) {
        Scalar a = pp.curve.getRandomScalar();
        r.r_1 = pp.P.mul(a);
        r.r_2 = pp.curve.Pairing(pp.P_pub.mul(a), pp.H_p(ID.L));
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
        AdditivePoint HL = pp.H(ID.L);
        r_p.r_1 = r.r_1.add(HL.mul(m.m.sub(m_p.m)));
        r_p.r_2 = r.r_2.mul(pp.curve.Pairing(HL, sk.S_ID).pow(m.m.sub(m_p.m)));
    }
}
