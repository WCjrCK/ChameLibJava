package ChameleonHash.CH.BaseCH.DKS_2020;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.BaseCH;
import EllipticCurve.Point.Scalar;

/*
 * Fully Collision-Resistant Chameleon-Hashes from Simpler and Post-Quantum Assumptions
 * P15. Construction 2: Concrete instantiation from DLOG
 */

public class Scheme
        extends ChameleonHash.CH.BaseCH.Scheme<PublicParam, PublicKey, SecretKey, Message, HashValue, Randomness>
        implements BaseCH<PublicParam, PublicKey, SecretKey, Message, HashValue, Randomness> {
    @Override
    public final PublicParam createPublicParam(CHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(PublicParam pp) {
        pp.g_1 = pp.curve.getRandomPoint(pp.curveGroup);
        pp.g_2 = pp.H_p(pp.g_1);
    }

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = pp.curve.getRandomScalar();
        pk.y = pp.g_1.pow(sk.x);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, PublicKey pk, Message m) {
        Scalar xi, k_1_1, k_1_2;
        xi = pp.curve.getRandomScalar();
        k_1_1 = pp.curve.getRandomScalar();
        k_1_2 = pp.curve.getRandomScalar();
        r.e_2 = pp.curve.getRandomScalar();
        r.s_2 = pp.curve.getRandomScalar();

        h.O = pp.g_1.pow(m.m).mul(pp.g_2.pow(xi));

        r.e_1 = pp.H(
                pk.y, h.O, m.m,
                pp.g_1.pow(k_1_1).mul(pp.g_2.pow(k_1_2)),
                pp.g_1.pow(r.s_2).div(pk.y.pow(r.e_2))
        ).sub(r.e_2);
        r.s_1_1 = k_1_1.add(r.e_1.mul(m.m));
        r.s_1_2 = k_1_2.add(r.e_1.mul(xi));
    }

    @Override
    public boolean Verify(PublicParam pp, PublicKey pk, Message m, HashValue h, Randomness r) {
        return r.e_1.add(r.e_2).isEqual(pp.H(
                pk.y, h.O, m.m,
                pp.g_1.pow(r.s_1_1).mul(pp.g_2.pow(r.s_1_2)).div(h.O.pow(r.e_1)),
                pp.g_1.pow(r.s_2).div(pk.y.pow(r.e_2))
        ));
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, PublicKey pk, SecretKey sk, Message m, HashValue h, Randomness r, Message m_p) {
        Scalar k_2 = pp.curve.getRandomScalar();
        r_p.e_1 = pp.curve.getRandomScalar();
        r_p.s_1_1 = pp.curve.getRandomScalar();
        r_p.s_1_2 = pp.curve.getRandomScalar();

        r_p.e_2 = pp.H(
                pk.y, h.O, m_p.m,
                pp.g_1.pow(r_p.s_1_1).mul(pp.g_2.pow(r_p.s_1_2)).div(h.O.pow(r_p.e_1)),
                pp.g_1.pow(k_2)
        ).sub(r_p.e_1);

        r_p.s_2 = k_2.add(r_p.e_2.mul(sk.x));
    }
}

