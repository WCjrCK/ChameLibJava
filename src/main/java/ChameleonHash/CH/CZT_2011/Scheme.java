package ChameleonHash.CH.CZT_2011;

import ChameleonHash.CH.CH;
import ChameleonHash.Config;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;

/*
 * Discrete logarithm based chameleon hashing and signatures without key exposure
 * P4. 4.1. The proposed chameleon hash scheme
 */

public class Scheme extends CH<PublicParam, PublicKey, SecretKey, Message, HashValue, Randomness> {
    @Override
    public final PublicParam createPublicParam(Config config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(PublicParam pp) {
        pp.g = pp.curve.getRandomPoint(pp.curveGroup);
    }

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = pp.curve.getRandomScalar();
        pk.y = pp.g.pow(sk.x);
    }

    private void calHash(HashValue h, Randomness r, PublicParam pp, PublicKey pk, Message m) {
        h.h = r.g_a.mul(pp.H(pk.y, m.I).pow(m.m));
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, PublicKey pk, Message m) {
        Scalar a = pp.curve.getRandomScalar();
        r.g_a = pp.g.pow(a);
        r.y_a = pk.y.pow(a);
        calHash(h, r, pp, pk, m);
    }

    @Override
    public boolean Verify(PublicParam pp, PublicKey pk, Message m, HashValue h, Randomness r) {
        HashValue tmp = new HashValue();
        calHash(tmp, r, pp, pk, m);
        return tmp.isEqual(h);
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, PublicKey pk, SecretKey sk, Message m, HashValue h, Randomness r, Message m_p) {
        MultivePoint H = pp.H(pk.y, m.I);
        Scalar delta = m.m.sub(m_p.m);
        r_p.y_a = r.y_a.mul(H.pow(delta.mul(sk.x)));
        r_p.g_a = r.g_a.mul(H.pow(delta));
        m_p.I = m.I;
    }
}

