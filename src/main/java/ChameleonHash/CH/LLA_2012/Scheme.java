package ChameleonHash.CH.LLA_2012;

import ChameleonHash.CH.CH;
import ChameleonHash.Config;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

/*
 * Key exposure free chameleon hash schemes based on discrete logarithm problem
 * P4. CH_inf: a key exposure free chameleon hash scheme
 */

public class Scheme extends CH<PublicParam, PublicKey, SecretKey, Message, HashValue, Randomness> {
    private LabelManager LM = new LabelManager();
    @Override
    public final PublicParam createPublicParam(Config config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(PublicParam pp) {}

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        pk.g = pp.curve.getRandomPoint(pp.curveGroup);
        sk.alpha = pp.curve.getRandomScalar();
        sk.x_1 = pp.curve.getRandomScalar();
        sk.x_2 = pp.curve.getRandomScalar();
        LabelGen lg = new LabelGen();
        lg.y_1 = pk.g.pow(sk.x_1);
        lg.omega_1 = lg.y_1.pow(sk.alpha);
        pk.y_2 = pk.g.pow(sk.x_2);
        LM.add(pp, pk, lg);
    }

    public void CalHash(HashValue h, PublicParam pp, PublicKey pk, Message m, Randomness r) {
        h.S = pk.g.pow(m.m)
                .mul(m.L.mul(
                        pk.y_2.pow(pp.H1(m.L, m.R, m.L)))
                        .pow(r.r));
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, PublicKey pk, Message m) {
        LM.get(m, pp, pk);
        r.r = pp.curve.getRandomScalar();
        CalHash(h, pp, pk, m, r);
    }

    @Override
    public boolean Verify(
            PublicParam pp,
            PublicKey pk,
            Message m,
            HashValue h,
            Randomness r
    ) {
        HashValue tmp = new HashValue();
        CalHash(tmp, pp, pk, m, r);
        return tmp.isEqual(h);
    }

    @Override
    public void Collision(
            Randomness r_p,
            PublicParam pp,
            PublicKey pk,
            SecretKey sk,
            Message m,
            HashValue h,
            Randomness r,
            Message m_p
    ) {
        MultivePoint t = m.R.div(m.L.pow(sk.alpha));
        Scalar H_2t = pp.H2(t);
        Scalar c = pp.H1(m.L, m.R, m.L);
        r_p.r = r.r.add(m.m.sub(m_p.m).div(sk.x_1.mul(H_2t).add(sk.x_2.mul(c))));

        m_p.L = m.L;
        m_p.R = m.R;
    }
}
