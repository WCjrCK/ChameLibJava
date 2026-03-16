package ChameleonHash.CH.BaseCH.DSS_2020;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.BaseCH;
import EllipticCurve.Point.Scalar;

/*
 * Reconstructing Chameleon Hash: Full Security and the Multi-Party Setting
 * P6. 3.2 ECC-based Construction
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
        pp.g = pp.curve.getRandomPoint(pp.curveGroup);
    }

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = pp.curve.getRandomScalar();
        pk.y = pp.g.pow(sk.x);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, PublicKey pk, Message m) {
        Scalar xi = pp.curve.getRandomScalar();
        Scalar k_1 = pp.curve.getRandomScalar();
        r.e_2 = pp.curve.getRandomScalar();
        r.s_2 = pp.curve.getRandomScalar();

        h.c_1 = pp.g.pow(xi);
        h.c_2 = m.m.mul(pk.y.pow(xi));

        r.e_1 = pp.H(
                pk.y, h.c_1, h.c_2, m.m,
                pp.g.pow(k_1), pk.y.pow(k_1), pp.g.pow(r.s_2).div(pk.y.pow(r.e_2))
        ).sub(r.e_2);
        r.s_1 = k_1.add(r.e_1.mul(xi));
    }

    @Override
    public boolean Verify(PublicParam pp, PublicKey pk, Message m, HashValue h, Randomness r) {
        return r.e_1.add(r.e_2).isEqual(pp.H(
                pk.y, h.c_1, h.c_2, m.m,
                pp.g.pow(r.s_1).div(h.c_1.pow(r.e_1)),
                pk.y.pow(r.s_1).div(h.c_2.div(m.m).pow(r.e_1)),
                pp.g.pow(r.s_2).div(pk.y.pow(r.e_2))
                )
        );
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, PublicKey pk, SecretKey sk, Message m, HashValue h, Randomness r, Message m_p) {
        Scalar k_2 = pp.curve.getRandomScalar();
        r_p.e_1 = pp.curve.getRandomScalar();
        r_p.s_1 = pp.curve.getRandomScalar();

        r_p.e_2 = pp.H(
                pk.y, h.c_1, h.c_2, m_p.m,
                pp.g.pow(r_p.s_1).div(h.c_1.pow(r_p.e_1)),
                pk.y.pow(r_p.s_1).div(h.c_2.div(m_p.m).pow(r_p.e_1)),
                pp.g.pow(k_2)
        ).sub(r_p.e_1);

        r_p.s_2 = k_2.add(r_p.e_2.mul(sk.x));
    }
}

