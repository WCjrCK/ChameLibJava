package scheme.CH.CH_ET_KOG_CDK_2017;

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.Mcl;
import utils.Hash;

import java.math.BigInteger;

/*
 * Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures
 * P12. Construction 2 (CHET in Known-Order Groups)
 */

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_G1 {
    public static class PublicParam {
        public SingleGroup.SingleGroupG1 GP = new SingleGroup.SingleGroupG1();
        public G1 g;
        public int lambda;

        public PublicParam(int lambda) {
            g = GP.GetGElement();
            this.lambda = lambda;
        }

        public Fr H(Fr m1) {
            return Hash.H_MCL_Zr_1(m1.toString());
        }
    }

    public static class PublicKey {
        public G1 h = new G1();
        public base.NIZK.MCL_G1.DL_Proof pi_pk;
        public AE.RSA.Native.PublicKey pk_enc = new AE.RSA.Native.PublicKey();
    }

    public static class SecretKey {
        public Fr x;
        public AE.RSA.Native.SecretKey sk_enc = new AE.RSA.Native.SecretKey();
    }

    public static class HashValue {
        public G1 b = new G1(), h_p = new G1();
        public base.NIZK.MCL_G1.DL_Proof pi_t;
    }

    public static class Randomness {
        public G1 p = new G1();
        public BigInteger C;
        public base.NIZK.MCL_G1.DL_Proof pi_p;
    }

    public static class ETrapdoor {
        public Fr etd;
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        sk.x = pp.GP.GetZrElement();
        Mcl.mul(pk.h, pp.g, sk.x);
        pk.pi_pk = new base.NIZK.MCL_G1.DL_Proof(sk.x, pp.g, pk.h);
        AE.RSA.Native.KeyGen(pk.pk_enc, sk.sk_enc, pp.lambda, pp.lambda);
    }

    public void Hash(HashValue H, Randomness R, ETrapdoor etd, PublicParam pp, PublicKey pk, Fr m) {
        if(!pk.pi_pk.Check(pp.g, pk.h)) throw new RuntimeException("not valid proof");
        Fr r = pp.GP.GetZrElement();
        etd.etd = pp.GP.GetZrElement();
        Mcl.mul(H.h_p, pp.g, etd.etd);
        H.pi_t = new base.NIZK.MCL_G1.DL_Proof(etd.etd, pp.g, H.h_p);
        R.C = AE.RSA.Native.Encrypt(new BigInteger(r.toString()), pk.pk_enc);
        Fr a = pp.H(m);
        Mcl.mul(R.p, pk.h, r);
        R.pi_p = new base.NIZK.MCL_G1.DL_Proof(r, pk.h, R.p);
        Mcl.mul(H.b, H.h_p, a);
        Mcl.add(H.b, H.b, R.p);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Fr m) {
        if(!R.pi_p.Check(pk.h, R.p) || !H.pi_t.Check(pp.g, H.h_p) || !pk.pi_pk.Check(pp.g, pk.h))
            throw new RuntimeException("not valid proof");
        Fr a = pp.H(m);
        G1 tmp = new G1();
        Mcl.mul(tmp, H.h_p, a);
        Mcl.add(tmp, tmp, R.p);
        return H.b.equals(tmp);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, ETrapdoor etd, PublicParam pp, PublicKey pk, SecretKey sk, Fr m, Fr m_p) {
        if(!Check(H, R, pp, pk, m)) throw new RuntimeException("not valid hash");
        Fr r = new Fr();
        r.setStr(AE.RSA.Native.Decrypt(R.C, pk.pk_enc, sk.sk_enc).toString());
        G1 tmp = new G1();
        Mcl.mul(tmp, pp.g, etd.etd);
        if(!H.h_p.equals(tmp)) throw new RuntimeException("not valid hash");
        Fr a = pp.H(m);
        Fr a_p = pp.H(m_p);
        Fr tmp_1 = new Fr();
        Mcl.mul(tmp_1, r, sk.x);
        Mcl.mul(tmp, pp.g, tmp_1);
        if(!R.p.equals(tmp)) throw new RuntimeException("not valid hash");
        if(a.equals(a_p)) {
            R_p.C = R.C;
            R_p.p = R.p;
            R_p.pi_p.CopyFrom(R.pi_p);
            return;
        }
        Fr r_p = new Fr();
        Mcl.sub(r_p, a, a_p);
        Mcl.mul(r_p, r_p, etd.etd);
        Mcl.div(r_p, r_p, sk.x);
        Mcl.add(r_p, r_p, r);
        Mcl.mul(R_p.p, pk.h, r_p);
        R_p.C = AE.RSA.Native.Encrypt(new BigInteger(r_p.toString()), pk.pk_enc);
        R_p.pi_p = new base.NIZK.MCL_G1.DL_Proof(r_p, pk.h, R_p.p);
    }
}
