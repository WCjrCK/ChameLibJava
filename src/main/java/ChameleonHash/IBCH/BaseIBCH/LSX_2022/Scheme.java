package ChameleonHash.IBCH.BaseIBCH.LSX_2022;

import ChameleonHash.Config;
import ChameleonHash.Interface.BaseIBCH;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Scalar;

/*
 * Efficient Identity-Based Chameleon Hash For Mobile Devices
 * P2. 3. PROPOSED EFFICIENT IB-CH
 */

public class Scheme
        extends ChameleonHash.IBCH.BaseIBCH.Scheme<PublicParam, MasterSecretKey, SecretKey, Identity, Message, HashValue, Randomness>
        implements BaseIBCH<PublicParam, MasterSecretKey, SecretKey, Identity, Message, HashValue, Randomness> {
    @Override
    public final PublicParam createPublicParam(Config config) {
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

    public void CalHash(HashValue h, PublicParam pp, Identity ID, Message m, Randomness r) {
        h.h = pp.eg_2g.pow(m.m).mul(pp.egg.pow(r.r_1)).mul(pp.curve.Pairing(r.r_2, pp.g_1.div(pp.g.pow(ID.ID))));
    }

    @Override
    public void Hash(
            HashValue h,
            Randomness r,
            PublicParam pp,
            Identity ID,
            Message m
    ) {
        r.r_1 = pp.curve.getRandomScalar();
        r.r_2 = pp.curve.getRandomPoint(CurveGroup.G1);
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
        Scalar delta_m = m.m.sub(m_p.m);
        r_p.r_1 = r.r_1.add(sk.td_1.mul(delta_m));
        r_p.r_2 = r.r_2.mul(sk.td_2.pow(delta_m));
    }
}
