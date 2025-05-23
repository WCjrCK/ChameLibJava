package scheme.CH.CH_ET_KOG_CDK_2017;

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.GT;
import com.herumi.mcl.Mcl;
import utils.Hash;

import java.math.BigInteger;

/*
 * Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures
 * P12. Construction 2 (CHET in Known-Order Groups)
 */

@SuppressWarnings("SuspiciousNameCombination")
public class MCL_GT {
    public static class PublicParam {
        public SingleGroup.SingleGroupGT GP = new SingleGroup.SingleGroupGT();
        public GT g = new GT();
        public int lambda;

        public PublicParam(int lambda) {
            GP.GetGElement(g);
            this.lambda = lambda;
        }

        public void H(Fr res, Fr m1) {
            Hash.H_MCL_Zr_1(res, m1.toString());
        }
    }

    public static class PublicKey {
        public GT h = new GT();
        public base.NIZK.MCL_GT.DL_Proof pi_pk;
        public AE.RSA.Native.PublicKey pk_enc = new AE.RSA.Native.PublicKey();
    }

    public static class SecretKey {
        public Fr x = new Fr();
        public AE.RSA.Native.SecretKey sk_enc = new AE.RSA.Native.SecretKey();
    }

    public static class HashValue {
        public GT b = new GT(), h_p = new GT();
        public base.NIZK.MCL_GT.DL_Proof pi_t;
    }

    public static class Randomness {
        public GT p = new GT();
        public BigInteger C;
        public base.NIZK.MCL_GT.DL_Proof pi_p;
    }

    public static class ETrapdoor {
        public Fr etd = new Fr();
    }

    private final GT[] G_tmp = new GT[]{new GT(), new GT()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr(), new Fr()};

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        pp.GP.GetZrElement(sk.x);
        Mcl.pow(pk.h, pp.g, sk.x);
        pk.pi_pk = new base.NIZK.MCL_GT.DL_Proof(sk.x, pp.g, pk.h, Fr_tmp);
        AE.RSA.Native.KeyGen(pk.pk_enc, sk.sk_enc, pp.lambda, pp.lambda);
    }

    public void Hash(HashValue H, Randomness R, ETrapdoor etd, PublicParam pp, PublicKey pk, Fr m) {
        if(!pk.pi_pk.Check(pp.g, pk.h, G_tmp, Fr_tmp)) throw new RuntimeException("not valid proof");
        pp.GP.GetZrElement(etd.etd);
        Mcl.pow(H.h_p, pp.g, etd.etd);
        H.pi_t = new base.NIZK.MCL_GT.DL_Proof(etd.etd, pp.g, H.h_p, Fr_tmp);
        R.C = AE.RSA.Native.Encrypt(new BigInteger(Fr_tmp[1].toString()), pk.pk_enc);
        Mcl.pow(R.p, pk.h, Fr_tmp[1]);
        R.pi_p = new base.NIZK.MCL_GT.DL_Proof(Fr_tmp[1], pk.h, R.p, Fr_tmp);
        pp.H(Fr_tmp[1], m);
        Mcl.pow(H.b, H.h_p, Fr_tmp[1]);
        Mcl.mul(H.b, H.b, R.p);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam pp, PublicKey pk, Fr m) {
        if(!R.pi_p.Check(pk.h, R.p, G_tmp, Fr_tmp) || !H.pi_t.Check(pp.g, H.h_p, G_tmp, Fr_tmp) || !pk.pi_pk.Check(pp.g, pk.h, G_tmp, Fr_tmp))
            throw new RuntimeException("not valid proof");
        pp.H(Fr_tmp[0], m);
        Mcl.pow(G_tmp[0], H.h_p, Fr_tmp[0]);
        Mcl.mul(G_tmp[0], G_tmp[0], R.p);
        return H.b.equals(G_tmp[0]);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, ETrapdoor etd, PublicParam pp, PublicKey pk, SecretKey sk, Fr m, Fr m_p) {
        if(!Check(H, R, pp, pk, m)) throw new RuntimeException("not valid hash");
        Mcl.pow(G_tmp[0], pp.g, etd.etd);
        if(!H.h_p.equals(G_tmp[0])) throw new RuntimeException("not valid hash");
        Fr_tmp[0].setStr(AE.RSA.Native.Decrypt(R.C, pk.pk_enc, sk.sk_enc).toString());
        Mcl.mul(Fr_tmp[1], Fr_tmp[0], sk.x);
        Mcl.pow(G_tmp[0], pp.g, Fr_tmp[1]);
        if(!R.p.equals(G_tmp[0])) throw new RuntimeException("not valid hash");

        pp.H(Fr_tmp[1], m);
        pp.H(Fr_tmp[2], m_p);

        if(Fr_tmp[1].equals(Fr_tmp[2])) {
            R_p.C = R.C;
            R_p.p = R.p;
            R_p.pi_p.CopyFrom(R.pi_p);
            return;
        }
        Mcl.sub(Fr_tmp[1], Fr_tmp[1], Fr_tmp[2]);
        Mcl.mul(Fr_tmp[1], Fr_tmp[1], etd.etd);
        Mcl.div(Fr_tmp[1], Fr_tmp[1], sk.x);
        Mcl.add(Fr_tmp[1], Fr_tmp[1], Fr_tmp[0]);
        Mcl.pow(R_p.p, pk.h, Fr_tmp[1]);
        R_p.C = AE.RSA.Native.Encrypt(new BigInteger(Fr_tmp[1].toString()), pk.pk_enc);
        R_p.pi_p = new base.NIZK.MCL_GT.DL_Proof(Fr_tmp[1], pk.h, R_p.p, Fr_tmp);
    }
}
