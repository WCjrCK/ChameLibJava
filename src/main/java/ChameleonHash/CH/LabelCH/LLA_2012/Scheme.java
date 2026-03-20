package ChameleonHash.CH.LabelCH.LLA_2012;

import ChameleonHash.CH.CH;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.LabelCH;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

/*
 * Key exposure free chameleon hash schemes based on discrete logarithm problem
 * P4. CH_inf: a key exposure free chameleon hash scheme
 */

public class Scheme extends CH
        implements LabelCH<PublicParam, PublicKey, SecretKey, Message, Label, HashValue, Randomness> {
    @Override
    public final PublicParam createPublicParam(CHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(PublicParam pp) {
        pp.g = pp.curve.getRandomPoint(pp.curveGroup);
    }

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.alpha = pp.curve.getRandomScalar();
        sk.x_1 = pp.curve.getRandomScalar();
        sk.x_2 = pp.curve.getRandomScalar();
        pk.y_1 = pp.g.pow(sk.x_1);
        pk.omega_1 = pk.y_1.pow(sk.alpha);
        pk.y_2 = pp.g.pow(sk.x_2);
    }

    public void CalHash(HashValue h, PublicParam pp, PublicKey pk, Message m, Label L, Randomness r) {
        h.S = pp.g.pow(m.m).mul(L.L.mul(pk.y_2.pow(pp.H1(L.L, L.R, L.L))).pow(r.r));
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, PublicKey pk, Message m, Label L) {
        MultivePoint t = pp.curve.getRandomPoint(pp.curveGroup);
        Scalar H_2t = pp.H2(t);
        L.L = pk.y_1.pow(H_2t);
        L.R = t.mul(pk.omega_1.pow(H_2t));
        r.r = pp.curve.getRandomScalar();
        CalHash(h, pp, pk, m, L, r);
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
        HashValue tmp = new HashValue();
        CalHash(tmp, pp, pk, m, L, r);
        return tmp.isEqual(h);
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
        MultivePoint t = L.R.div(L.L.pow(sk.alpha));
        Scalar H_2t = pp.H2(t);
        Scalar c = pp.H1(L.L, L.R, L.L);
        r_p.r = r.r.add(m.m.sub(m_p.m).div(sk.x_1.mul(H_2t).add(sk.x_2.mul(c))));
    }
}
