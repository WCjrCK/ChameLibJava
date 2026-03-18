package ChameleonHash.CH.LabelCH.CZK_2004;

import ChameleonHash.CH.CH;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.LabelCH;
import EllipticCurve.Point.Scalar;

/*
 * Chameleon Hashing without Key Exposure
 * P7. 3.3.1 The scheme
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
        sk.x = pp.curve.getRandomScalar();
        pk.y = pp.g.pow(sk.x);
    }

    private void calHash(HashValue h, Randomness r, PublicParam pp, Message m, Label L) {
        h.h = pp.g.mul(L.I).pow(m.m).mul(r.y_a);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, PublicKey pk, Message m, Label L) {
        Scalar a = pp.curve.getRandomScalar();
        r.g_a = pp.g.pow(a);
        r.y_a = pk.y.pow(a);
        calHash(h, r, pp, m, L);
    }

    @Override
    public boolean Verify(PublicParam pp, PublicKey pk, Message m, Label L, HashValue h, Randomness r) {
        HashValue tmp = new HashValue();
        calHash(tmp, r, pp, m, L);
        return tmp.isEqual(h);
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, PublicKey pk, SecretKey sk, Message m, Label L, HashValue h, Randomness r, Message m_p) {
        r_p.g_a = pp.g.mul(L.I);
        Scalar delta = m.m.sub(m_p.m);
        r_p.y_a = r.y_a.mul(r_p.g_a.pow(delta));
        r_p.g_a = r.g_a.mul(r_p.g_a.pow(delta.div(sk.x)));
    }
}

