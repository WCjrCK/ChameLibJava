package ChameleonHash.CH.LabelCH.AM_2004;

import ChameleonHash.CH.CH;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.LabelCH;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Scalar;

/*
 * On the Key Exposure Problem in Chameleon Hashes
 * P12. Scheme based on SDH and DL
 */

public class Scheme extends CH
        implements LabelCH<PublicParam, PublicKey, SecretKey, Message, Label, HashValue, Randomness> {
    @Override
    public final PublicParam createPublicParam(CHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(PublicParam pp) {
        pp.g = pp.curve.getRandomPoint(CurveGroup.G1);
    }

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = pp.curve.getRandomScalar();
        pk.h = pp.g.pow(sk.x);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, PublicKey pk, Message m, Label L) {
        Scalar r_ = pp.curve.getRandomScalar();
        r.g_r = pp.g.pow(r_);
        h.h = pp.g.pow(pp.H(m.m)).mul(r.g_r.pow(pp.H(L.L)).mul(pk.h.pow(r_)));
    }

    @Override
    public boolean Verify(
            PublicParam pp,
            PublicKey pk,
            Message m,
            Label L,
            HashValue h,
            Randomness r
    ) {
        return pp.curve.Pairing(pp.g, h.h.div(pp.g.pow(pp.H(m.m)))).isEqual(pp.curve.Pairing(r.g_r, pp.g.pow(pp.H(L.L)).mul(pk.h)));
    }

    @Override
    public void Collision(
            Randomness r_p,
            PublicParam pp,
            PublicKey pk,
            SecretKey sk,
            Message m,
            Label L,
            HashValue h,
            Randomness r,
            Message m_p
    ) {
        Scalar e = pp.H(L.L);
        Scalar x_e = sk.x.add(e);
        Scalar H_m_p = pp.H(m_p.m);
        r_p.g_r = r.g_r.mul(pp.g.pow(pp.H(m.m).sub(H_m_p).div(x_e)));
    }
}
