package ChameleonHash.CH.LabelCH.AM_2004;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.LabelCH;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

/*
 * Key exposure free chameleon hash schemes based on discrete logarithm problem
 * P4. CH_inf: a key exposure free chameleon hash scheme
 */

public class Scheme
        extends ChameleonHash.CH.LabelCH.Scheme<PublicParam, PublicKey, SecretKey, Message, Label, HashValue, Randomness>
        implements LabelCH<PublicParam, PublicKey, SecretKey, Message, Label, HashValue, Randomness> {
    @Override
    public final PublicParam createPublicParam(CHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(PublicParam pp) {}

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = pp.curve.getRandomScalar();
        pk.g = pp.curve.getRandomPoint(pp.curveGroup);
        pk.h = pk.g.pow(sk.x);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, PublicKey pk, Message m, Label L) {
        Scalar r_ = pp.curve.getRandomScalar();
        r.g_r = pk.g.pow(r_);
        MultivePoint geh = pk.g.pow(pp.H(L.L)).mul(pk.h);
        MultivePoint gehr = geh.pow(r_);
        h.h = pk.g.pow(pp.H(m.m)).mul(gehr);
        r.pi = pp.nizkScheme.Commitment(pp.nizkScheme.createRelation(r_, pk.g, r.g_r, geh, gehr));
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
        MultivePoint geh = pk.g.pow(pp.H(L.L)).mul(pk.h);
        MultivePoint gehr = h.h.div(pk.g.pow(pp.H(m.m)));
        return r.pi.Check(pp.nizkScheme.createRelation(pk.g, r.g_r, geh, gehr)) ||
                r.pi.Check(pp.nizkScheme.createRelation(pk.g, geh, r.g_r, gehr));
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
        r_p.g_r = r.g_r.mul(pk.g.pow(pp.H(m.m).sub(H_m_p).div(x_e)));
        r_p.pi = pp.nizkScheme.Commitment(pp.nizkScheme.createRelation(x_e, pk.g, pk.g.pow(e).mul(pk.h), r_p.g_r, h.h.div(pk.g.pow(H_m_p))));
    }
}
