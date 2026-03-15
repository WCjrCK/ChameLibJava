package ChameleonHash.CH.BaseCH.CCT_2024;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.BaseCH;
import EllipticCurve.Point.MultivePoint;
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
        pk.g_x = pp.g.pow(sk.x);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, PublicKey pk, Message m) {
        Scalar rho = pp.curve.getRandomScalar();
        h.h = pp.g.pow(rho);

        r.z_1 = pp.curve.getRandomScalar();
        r.z_2 = pp.curve.getRandomScalar();

        r.c_1 = pp.H_p(pp.g.pow(r.z_2), pk.g_x, h.h, m.m);
        r.z_2 = r.z_2.sub(pp.H_p(pp.g.pow(r.z_1).mul(pk.g_x.pow(r.c_1)), pk.g_x, h.h, m.m).mul(rho));

        h.h = h.h.mul(pp.H(m.m));
    }

    @Override
    public boolean Verify(PublicParam pp, PublicKey pk, Message m, HashValue h, Randomness r) {
        MultivePoint y_p = h.h.div(pp.H(m.m));

        return r.c_1.isEqual(pp.H_p(
                pp.g.pow(r.z_2).mul(y_p.pow(pp.H_p(
                        pp.g.pow(r.z_1).mul(pk.g_x.pow(r.c_1)), pk.g_x, y_p, m.m
                ))), pk.g_x, y_p, m.m
        ));
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, PublicKey pk, SecretKey sk, Message m, HashValue h, Randomness r, Message m_p) {
        MultivePoint y_p = h.h.div(pp.H(m_p.m));

        r_p.z_1 = pp.curve.getRandomScalar();
        r_p.z_2 = pp.curve.getRandomScalar();

        r_p.c_1 = pp.H_p(
                pp.g.pow(r_p.z_2).mul(y_p.pow(pp.H_p(
                        pp.g.pow(r_p.z_1), pk.g_x, y_p, m_p.m
                ))), pk.g_x, y_p, m_p.m
        );
        r_p.z_1 = r_p.z_1.sub(r_p.c_1.mul(sk.x));
    }
}

