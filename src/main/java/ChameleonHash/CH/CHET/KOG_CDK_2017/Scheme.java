package ChameleonHash.CH.CHET.KOG_CDK_2017;

import ChameleonHash.CH.CH;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.CHET;
import EllipticCurve.Point.Scalar;
import Encryption.PKE.Components.PlainText;

/*
 * Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures
 * P12. Construction 2 (CHET in Known-Order Groups)
 */

public class Scheme extends CH
        implements CHET<PublicParam, PublicKey, SecretKey, Message, ETrapdoor, HashValue, Randomness> {
    @Override
    public final PublicParam createPublicParam(CHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public final void Setup(PublicParam pp) {
        pp.g = pp.curve.getRandomPoint(pp.curveGroup);
        pp.PKEScheme.Setup(pp.pke_pp);
    }

    @Override
    public final void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = pp.curve.getRandomScalar();
        pk.h = pp.g.pow(sk.x);
        pk.pi_pk = pp.NIZK_DL.Prove(pp.NIZK_DL.createRelation(sk.x, pp.g, pk.h));
        pp.PKEScheme.KeyGen(pk.pke_pk, sk.pke_sk, pp.pke_pp);
    }

    @Override
    public final void Hash(HashValue h, Randomness r, ETrapdoor etd, PublicParam pp, PublicKey pk, Message m) {
        if(!pk.pi_pk.Check(pp.NIZK_DL.createRelation(pp.g, pk.h))) throw new RuntimeException("NIZK验证失败");
        Scalar r_ = pp.curve.getRandomScalar();
        etd.etd = pp.curve.getRandomScalar();
        h.h_p = pp.g.pow(etd.etd);
        h.pi_t = pp.NIZK_DL.Prove(pp.NIZK_DL.createRelation(etd.etd, pp.g, h.h_p));
        pp.PKEScheme.Encrypt(r.C, pp.pke_pp, pk.pke_pk, pp.pke_pp.createPlainText(r_.toString()));
        Scalar a = pp.H(m.m);
        r.p = pk.h.pow(r_);
        r.pi_p = pp.NIZK_DL.Prove(pp.NIZK_DL.createRelation(r_, pk.h, r.p));
        h.b = r.p.mul(h.h_p.pow(a));
    }

    @Override
    public final boolean Verify(PublicParam pp, PublicKey pk, Message m, HashValue h, Randomness r) {
        if(!r.pi_p.Check(pp.NIZK_DL.createRelation(pk.h, r.p)) || !h.pi_t.Check(pp.NIZK_DL.createRelation(pp.g, h.h_p)) || !pk.pi_pk.Check(pp.NIZK_DL.createRelation(pp.g, pk.h))) return false;
        return h.b.isEqual(r.p.mul(h.h_p.pow(pp.H(m.m))));
    }

    @Override
    public final void Collision(Randomness r_p, PublicParam pp, PublicKey pk, SecretKey sk, Message m, ETrapdoor etd, HashValue h, Randomness r, Message m_p) {
        if(!Verify(pp, pk, m, h, r)) throw new RuntimeException("校验失败");
        if(!h.h_p.isEqual(pp.g.pow(etd.etd))) throw new RuntimeException("校验失败");

        PlainText pke_pt = pp.pke_pp.createPlainText("");
        pp.PKEScheme.Decrypt(pke_pt, pp.pke_pp, pk.pke_pk, sk.pke_sk, r.C);
        Scalar r_ = pp.curve.createScalarFromString(pke_pt.toString());
        if(!r.p.isEqual(pk.h.pow(r_))) throw new RuntimeException("校验失败");

        Scalar a = pp.H(m.m);
        Scalar a_p = pp.H(m_p.m);

        if(a.isEqual(a_p)) {
            r_p.C = r.C;
            r_p.p = r.p;
            r_p.pi_p.CopyFrom(r.pi_p);
            return;
        }
        Scalar r_p_ = r_.add(a.sub(a_p).mul(etd.etd).div(sk.x));
        r_p.p = pk.h.pow(r_p_);
        pp.PKEScheme.Encrypt(r_p.C, pp.pke_pp, pk.pke_pk, pp.pke_pp.createPlainText(r_p_.toString()));
        r_p.pi_p = pp.NIZK_DL.Prove(pp.NIZK_DL.createRelation(r_p_, pk.h, r_p.p));
    }
}

