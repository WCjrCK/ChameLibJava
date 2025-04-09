package scheme.PBCH.PCHBA_TLL_2020;

import com.herumi.mcl.*;
import utils.BooleanFormulaParser;
import utils.Func;
import utils.Hash;

import java.util.Arrays;
import java.util.Map;
import java.util.Random;

/*
 * Policy-based Chameleon Hash for Blockchain Rewriting with Black-box Accountability
 * P8. 6.2 Instantiation
 */

public class MCL_swap {
    public static class PublicParam {
        public ABE.FAME.MCL_swap.PublicParam pp_FAME = new ABE.FAME.MCL_swap.PublicParam();
        public Random rand = new Random();

        public void H2(Fr res, String m) {
            Hash.H_MCL_Zr_1(res, m);
        }
    }

    public static class MasterPublicKey {
        //        g1~k, galpha1~k, h1~k, galpha, hd/alpha, h1/alpha, hbeta/alpha
        public ABE.FAME.MCL_swap.MasterPublicKey mpk_FAME = new ABE.FAME.MCL_swap.MasterPublicKey();
        public G2 g_alpha = new G2();
        public G1 h_d_alpha = new G1(), h_1_alpha = new G1(), h_beta_alpha = new G1(), pk_ch = new G1();
        public G2[] g_i, g_alpha_i;
        public G1[] h_i;
    }

    public static class MasterSecretKey {
        public ABE.FAME.MCL_swap.MasterSecretKey msk_FAME = new ABE.FAME.MCL_swap.MasterSecretKey();
//        alpha, beta, z1~k
        public Fr alpha = new Fr(), beta = new Fr(), sk_ch = new Fr();
        public Fr[] z_i;
    }

    public static class SecretKey {
        public ABE.FAME.MCL_swap.SecretKey sk_FAME = new ABE.FAME.MCL_swap.SecretKey();
        public G2[] sk_0_g = new G2[]{new G2(), new G2(), new G2()};
        public G2 sk_1 = new G2();
        public Fr sk_ch = new Fr();
        public G2[] sk_2;
        private final Fr delegate_z = new Fr();

        private final G2[] G2_tmp = new G2[]{new G2(), new G2(), new G2()};
        private final G1[] G1_tmp = new G1[]{new G1()};
        private final Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr(), new Fr(), new Fr(), new Fr(), new Fr(), new Fr(), new Fr()};

        public void CopyFrom(SecretKey sk) {
            sk_FAME.CopyFrom(sk.sk_FAME);
            for (int i = 0;i < sk_0_g.length; ++i) {
                Mcl.neg(sk_0_g[i], sk.sk_0_g[i]);
                Mcl.neg(sk_0_g[i], sk_0_g[i]);
            }
            sk_2 = new G2[sk.sk_2.length];
            for (int i = 0;i < sk_2.length; ++i) {
                sk_2[i] = new G2();
                Mcl.neg(sk_2[i], sk.sk_2[i]);
                Mcl.neg(sk_2[i], sk_2[i]);
            }
            Mcl.neg(sk_1, sk.sk_1);
            Mcl.neg(sk_1, sk_1);
            Mcl.neg(sk_ch, sk.sk_ch);
            Mcl.neg(sk_ch, sk_ch);
        }

        public boolean delegate(PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, G2 ID_i_1, Fr I_i_1) {
//            mod.ssk.sk_FAME, SP.pp_FAME, mpk.mpk_FAME, msk.msk_FAME, S, r_1, r_2, R
            if(sk_2.length == 0) return false;
            Func.GetMCLZrRandomElement(Fr_tmp[0]);
            Func.GetMCLZrRandomElement(Fr_tmp[1]);

            Mcl.mul(Fr_tmp[2], msk.msk_FAME.b_1, Fr_tmp[0]);
            Mcl.mul(Fr_tmp[3], msk.msk_FAME.b_2, Fr_tmp[1]);

            Mcl.add(Fr_tmp[0], Fr_tmp[0], Fr_tmp[1]);
            Mcl.add(delegate_z, delegate_z, Fr_tmp[0]);

            Mcl.mul(G1_tmp[0], mpk.mpk_FAME.h, Fr_tmp[2]);
            Mcl.add(sk_FAME.sk_0[0], sk_FAME.sk_0[0], G1_tmp[0]);

            Mcl.div(Fr_tmp[4], Fr_tmp[2], msk.msk_FAME.a_2);
            Mcl.div(Fr_tmp[2], Fr_tmp[2], msk.msk_FAME.a_1);

            Mcl.mul(G1_tmp[0], mpk.mpk_FAME.h, Fr_tmp[3]);
            Mcl.add(sk_FAME.sk_0[1], sk_FAME.sk_0[1], G1_tmp[0]);

            Mcl.div(Fr_tmp[5], Fr_tmp[3], msk.msk_FAME.a_2);
            Mcl.div(Fr_tmp[3], Fr_tmp[3], msk.msk_FAME.a_1);

            Mcl.mul(G1_tmp[0], mpk.h_1_alpha, Fr_tmp[0]);
            Mcl.add(sk_FAME.sk_0[2], sk_FAME.sk_0[2], G1_tmp[0]);

            Mcl.mul(G2_tmp[0], sk_0_g[0], Fr_tmp[0]);
            Mcl.add(sk_0_g[1], sk_0_g[1], G2_tmp[0]);

            Mcl.mul(Fr_tmp[6], msk.alpha, msk.msk_FAME.a_1);
            Mcl.mul(Fr_tmp[7], msk.alpha, msk.msk_FAME.a_2);

            Mcl.div(Fr_tmp[6], Fr_tmp[0], Fr_tmp[6]);
            Mcl.div(Fr_tmp[7], Fr_tmp[0], Fr_tmp[7]);

            for(Map.Entry<String, Integer> entry : sk_FAME.Attr2id.entrySet()) {
                SP.pp_FAME.H(G2_tmp[0], entry.getKey() + "11");
                Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[2]);

                SP.pp_FAME.H(G2_tmp[1], entry.getKey() + "21");
                Mcl.mul(G2_tmp[1], G2_tmp[1], Fr_tmp[3]);

                SP.pp_FAME.H(G2_tmp[2], entry.getKey() + "31");
                Mcl.mul(G2_tmp[2], G2_tmp[2], Fr_tmp[6]);

                Mcl.add(sk_FAME.sk_y[entry.getValue()][0], sk_FAME.sk_y[entry.getValue()][0], G2_tmp[0]);
                Mcl.add(sk_FAME.sk_y[entry.getValue()][0], sk_FAME.sk_y[entry.getValue()][0], G2_tmp[1]);
                Mcl.add(sk_FAME.sk_y[entry.getValue()][0], sk_FAME.sk_y[entry.getValue()][0], G2_tmp[2]);

                SP.pp_FAME.H(G2_tmp[0], entry.getKey() + "12");
                Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[4]);

                SP.pp_FAME.H(G2_tmp[1], entry.getKey() + "22");
                Mcl.mul(G2_tmp[1], G2_tmp[1], Fr_tmp[5]);

                SP.pp_FAME.H(G2_tmp[2], entry.getKey() + "32");
                Mcl.mul(G2_tmp[2], G2_tmp[2], Fr_tmp[7]);

                Mcl.add(sk_FAME.sk_y[entry.getValue()][1], sk_FAME.sk_y[entry.getValue()][1], G2_tmp[0]);
                Mcl.add(sk_FAME.sk_y[entry.getValue()][1], sk_FAME.sk_y[entry.getValue()][1], G2_tmp[1]);
                Mcl.add(sk_FAME.sk_y[entry.getValue()][1], sk_FAME.sk_y[entry.getValue()][1], G2_tmp[2]);
            }

            SP.pp_FAME.H(G2_tmp[0], "0111");
            Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[2]);

            SP.pp_FAME.H(G2_tmp[1], "0121");
            Mcl.mul(G2_tmp[1], G2_tmp[1], Fr_tmp[3]);

            SP.pp_FAME.H(G2_tmp[2], "0131");
            Mcl.mul(G2_tmp[2], G2_tmp[2], Fr_tmp[6]);

            Mcl.add(sk_FAME.sk_p[0], sk_FAME.sk_p[0], G2_tmp[0]);
            Mcl.add(sk_FAME.sk_p[0], sk_FAME.sk_p[0], G2_tmp[1]);
            Mcl.add(sk_FAME.sk_p[0], sk_FAME.sk_p[0], G2_tmp[2]);

            SP.pp_FAME.H(G2_tmp[0], "0112");
            Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[4]);

            SP.pp_FAME.H(G2_tmp[1], "0122");
            Mcl.mul(G2_tmp[1], G2_tmp[1], Fr_tmp[5]);

            SP.pp_FAME.H(G2_tmp[2], "0132");
            Mcl.mul(G2_tmp[2], G2_tmp[2], Fr_tmp[7]);

            Mcl.add(sk_FAME.sk_p[1], sk_FAME.sk_p[1], G2_tmp[0]);
            Mcl.add(sk_FAME.sk_p[1], sk_FAME.sk_p[1], G2_tmp[1]);
            Mcl.add(sk_FAME.sk_p[1], sk_FAME.sk_p[1], G2_tmp[2]);

            Mcl.mul(G2_tmp[0], ID_i_1, Fr_tmp[0]);
            Mcl.mul(G2_tmp[1], sk_2[0], I_i_1);
            Mcl.add(sk_1, sk_1, G2_tmp[0]);
            Mcl.add(sk_1, sk_1, G2_tmp[1]);

            sk_2 = Arrays.copyOfRange(sk_2, 1, sk_2.length);

            Mcl.mul(G2_tmp[0], mpk.g_alpha_i[sk_2.length - 1], delegate_z);
            Mcl.add(sk_2[0], sk_2[0], G2_tmp[0]);

            return true;
        }
    }

    public static class HashValue {
        G1 b = new G1(), h_p = new G1();
        Fr[] owner_ID;
    }

    public static class Randomness {
        public ABE.FAME.MCL_swap.CipherText ct_FAME = new ABE.FAME.MCL_swap.CipherText();
        Fr sigma = new Fr();
        G2 epk = new G2();
        G1 p = new G1(), ct_0_4 = new G1(), ct_1 = new G1(), ct_2 = new G1(), ct_3 = new G1(), c = new G1();
        byte[] ct, ct_p;
    }

    public static class User {
        private final SecretKey ssk = new SecretKey();
        public G2 ID_hat = new G2();
        public G1 ID_hat_h = new G1(), ID_hat_alpha = new G1();
        public Fr[] ID;

        private final G2[] G2_tmp = new G2[]{new G2()};
        private final G1[] G1_tmp = new G1[]{new G1()};
        private final Fr[] Fr_tmp = new Fr[]{new Fr()};

        public User(int len) {
            ID = new Fr[len];
            for (int i = 0; i < len; ++i) {
                ID[i] = new Fr();
                Func.GetMCLZrRandomElement(ID[i]);
            }
        }

        public User(User f, int len) {
            ID = new Fr[len];
            for (int i = 0; i < len; ++i) ID[i] = new Fr();
            for (int i = 0; i < f.ID.length; ++i) {
                Mcl.neg(ID[i], f.ID[i]);
                Mcl.neg(ID[i], ID[i]);
            }
            for (int i = f.ID.length; i < len; ++i) Func.GetMCLZrRandomElement(ID[i]);
        }

        @SuppressWarnings("CopyConstructorMissesField")
        public User(User u) {
            ssk.CopyFrom(u.ssk);
            Mcl.neg(ID_hat_alpha, u.ID_hat_alpha);
            Mcl.neg(ID_hat_alpha, ID_hat_alpha);
            Mcl.neg(ID_hat, u.ID_hat);
            Mcl.neg(ID_hat, ID_hat);
            Mcl.neg(ID_hat_h, u.ID_hat_h);
            Mcl.neg(ID_hat_h, ID_hat_h);
            ID = new Fr[u.ID.length];
            for (int i = 0; i < u.ID.length; ++i) {
                ID[i] = new Fr();
                Mcl.neg(ID[i], u.ID[i]);
                Mcl.neg(ID[i], ID[i]);
            }
            Mcl.sub(ssk.delegate_z, ID[0], ID[0]);
        }

        public boolean delegate(PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, Fr I_i_1) {
            ID = Arrays.copyOf(ID, ID.length + 1);
            ID[ID.length - 1] = new Fr(I_i_1);
            Mcl.mul(G2_tmp[0], mpk.g_i[mpk.g_i.length - ID.length], I_i_1);
            Mcl.add(ID_hat, ID_hat, G2_tmp[0]);

            Mcl.mul(G1_tmp[0], mpk.h_i[mpk.h_i.length - ID.length], I_i_1);
            Mcl.add(ID_hat_h, ID_hat_h, G1_tmp[0]);

            Mcl.mul(Fr_tmp[0], I_i_1, msk.alpha);

            Mcl.mul(G1_tmp[0], mpk.h_i[mpk.h_i.length - ID.length], Fr_tmp[0]);
            Mcl.add(ID_hat_alpha, ID_hat_alpha, G1_tmp[0]);

            Mcl.mul(G2_tmp[0], ID_hat, msk.alpha);

            return ssk.delegate(SP, mpk, msk, G2_tmp[0], I_i_1);
        }
    }

    ABE.FAME.MCL_swap FAME = new ABE.FAME.MCL_swap();

    private final G2[] G2_tmp = new G2[]{new G2()};
    private final G1[] G1_tmp = new G1[]{new G1()};
    private final GT[] GT_tmp = new GT[]{new GT(), new GT(), new GT()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr(), new Fr(), new Fr()};


    public void SetUp(MasterPublicKey mpk, MasterSecretKey msk, int k) {
        Func.GetMCLZrRandomElement(Fr_tmp[0]);
        Func.GetMCLZrRandomElement(Fr_tmp[1]);
        Func.GetMCLZrRandomElement(Fr_tmp[2]);

        Func.GetMCLZrRandomElement(msk.alpha);
        Func.GetMCLZrRandomElement(msk.beta);

        msk.z_i = new Fr[k];

        for(int i = 0; i < k; ++i) {
            msk.z_i[i] = new Fr();
            Func.GetMCLZrRandomElement(msk.z_i[i]);
        }

        FAME.SetUp(mpk.mpk_FAME, msk.msk_FAME, Fr_tmp[0], Fr_tmp[1], Fr_tmp[2], msk.alpha);
        mpk.g_i = new G2[k];
        for(int i = 0; i < k; ++i) {
            mpk.g_i[i] = new G2();
            Mcl.mul(mpk.g_i[i], mpk.mpk_FAME.g, msk.z_i[i]);
        }
        mpk.g_alpha_i = new G2[k];
        for(int i = 0; i < k; ++i) {
            mpk.g_alpha_i[i] = new G2();
            Mcl.mul(mpk.g_alpha_i[i], mpk.g_i[i], msk.alpha);
        }
        mpk.h_i = new G1[k];
        for(int i = 0; i < k; ++i) {
            mpk.h_i[i] = new G1();
            Mcl.mul(mpk.h_i[i], mpk.mpk_FAME.h, msk.z_i[i]);
        }

        Mcl.mul(mpk.g_alpha, mpk.mpk_FAME.g, msk.alpha);

        Mcl.add(Fr_tmp[0], Fr_tmp[0], Fr_tmp[1]);
        Mcl.add(Fr_tmp[0], Fr_tmp[0], Fr_tmp[2]);
        Mcl.div(Fr_tmp[0], Fr_tmp[0], msk.alpha);
        Mcl.mul(mpk.h_d_alpha, mpk.mpk_FAME.h, Fr_tmp[0]);

        Mcl.inv(Fr_tmp[0], msk.alpha);
        Mcl.mul(mpk.h_1_alpha, mpk.mpk_FAME.h, Fr_tmp[0]);

        Mcl.mul(Fr_tmp[0], msk.beta, Fr_tmp[0]);
        Mcl.mul(mpk.h_beta_alpha, mpk.mpk_FAME.h, Fr_tmp[0]);

        Func.GetMCLZrRandomElement(msk.sk_ch);
        Mcl.mul(mpk.pk_ch, mpk.mpk_FAME.h, msk.sk_ch);
    }

    public void AssignUser(User usr, MasterPublicKey mpk, MasterSecretKey msk) {
        Mcl.neg(usr.ID_hat, mpk.mpk_FAME.g);
        Mcl.neg(usr.ID_hat, usr.ID_hat);
        Mcl.neg(usr.ID_hat_h, mpk.mpk_FAME.h);
        Mcl.neg(usr.ID_hat_h, usr.ID_hat_h);
        for(int i = 0;i < usr.ID.length;++i) {
            Mcl.mul(G2_tmp[0], mpk.g_i[mpk.g_i.length - i - 1], usr.ID[i]);
            Mcl.add(usr.ID_hat, usr.ID_hat, G2_tmp[0]);
            Mcl.mul(G1_tmp[0], mpk.h_i[mpk.g_i.length - i - 1], usr.ID[i]);
            Mcl.add(usr.ID_hat_h, usr.ID_hat_h, G1_tmp[0]);
        }
        Mcl.mul(usr.ID_hat_alpha, usr.ID_hat_h, msk.alpha);
    }

    public void KeyGen(User mod, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, BooleanFormulaParser.AttributeList S) {
        Func.GetMCLZrRandomElement(Fr_tmp[0]);
        Func.GetMCLZrRandomElement(Fr_tmp[1]);
        FAME.KeyGen(mod.ssk.sk_FAME, SP.pp_FAME, mpk.mpk_FAME, msk.msk_FAME, S, Fr_tmp[0], Fr_tmp[1], msk.alpha);
        Mcl.add(Fr_tmp[0], Fr_tmp[0], Fr_tmp[1]);
        Func.GetMCLZrRandomElement(Fr_tmp[1]);
        Mcl.inv(Fr_tmp[2], msk.alpha);
        Mcl.mul(mod.ssk.sk_0_g[0], mpk.mpk_FAME.g, Fr_tmp[2]);
        Mcl.mul(Fr_tmp[2], Fr_tmp[0], Fr_tmp[2]);
        Mcl.mul(mod.ssk.sk_FAME.sk_0[2], mpk.mpk_FAME.h, Fr_tmp[2]);
        Mcl.mul(mod.ssk.sk_0_g[1], mpk.mpk_FAME.g, Fr_tmp[2]);
        Mcl.mul(mod.ssk.sk_0_g[2], mpk.mpk_FAME.g, Fr_tmp[1]);

        Mcl.mul(Fr_tmp[0], Fr_tmp[0], msk.alpha);
        Mcl.mul(Fr_tmp[1], Fr_tmp[1], msk.beta);

        Mcl.mul(mod.ssk.sk_1, mpk.mpk_FAME.g, Fr_tmp[1]);
        Mcl.mul(G2_tmp[0], mod.ID_hat, Fr_tmp[0]);
        Mcl.add(mod.ssk.sk_1, mod.ssk.sk_1, G2_tmp[0]);
        Mcl.add(mod.ssk.sk_1, mod.ssk.sk_1, msk.msk_FAME.g_d3);
        Mcl.add(mod.ssk.sk_1, mod.ssk.sk_1, msk.msk_FAME.g_d2);
        Mcl.add(mod.ssk.sk_1, mod.ssk.sk_1, msk.msk_FAME.g_d1);

        mod.ssk.sk_2 = new G2[mpk.g_i.length - mod.ID.length];
        for(int i = 0;i < mod.ssk.sk_2.length;++i) {
            mod.ssk.sk_2[i] = new G2();
            Mcl.mul(mod.ssk.sk_2[i], mpk.g_i[mod.ssk.sk_2.length - i - 1], Fr_tmp[0]);
        }
        Mcl.neg(mod.ssk.sk_ch, msk.sk_ch);
        Mcl.neg(mod.ssk.sk_ch, mod.ssk.sk_ch);
    }

    private void GenCipher(Randomness R, PublicParam SP, MasterPublicKey mpk, User owner, base.LSSS.MCL.Matrix MSP, Fr r, byte[] R_) {
        Func.GetMCLZrRandomElement(Fr_tmp[0]);
        Func.GetMCLZrRandomElement(Fr_tmp[1]);
        Func.GetMCLGTRandomElement(GT_tmp[0]);
        Mcl.inv(GT_tmp[1], GT_tmp[0]);
        Mcl.mul(GT_tmp[0], GT_tmp[0], GT_tmp[1]);
        FAME.Encrypt(R.ct_FAME, SP.pp_FAME, mpk.mpk_FAME, MSP, new ABE.FAME.MCL_swap.PlainText(GT_tmp[0]), Fr_tmp[0], Fr_tmp[1]);
        Mcl.add(Fr_tmp[0], Fr_tmp[0], Fr_tmp[1]);
        Mcl.mul(R.p, mpk.pk_ch, r);

        Mcl.mul(R.ct_FAME.ct_0[2], mpk.h_1_alpha, Fr_tmp[0]);
        Mcl.mul(R.ct_0_4, mpk.h_beta_alpha, Fr_tmp[0]);

        R.ct = R.ct_FAME.ct_p.serialize();
        Mcl.inv(R.ct_FAME.ct_p, GT_tmp[0]);
        byte[] tmp = r.serialize();
        for(int i = 0;i < tmp.length;++i) R.ct[i] ^= tmp[i];

        Mcl.pairing(GT_tmp[0], mpk.h_d_alpha, mpk.mpk_FAME.g);
        Mcl.pow(GT_tmp[0], GT_tmp[0], Fr_tmp[0]);

        SP.H2(Fr_tmp[1], GT_tmp[0].toString());

        R.ct_p = Fr_tmp[1].serialize();
        for(int i = 0;i < R_.length;++i) R.ct_p[i] ^= R_[i];

        Mcl.mul(R.ct_1, owner.ID_hat_alpha, Fr_tmp[0]);
        Mcl.mul(R.ct_2, owner.ID_hat_h, Fr_tmp[0]);
        Mcl.mul(R.ct_3, R.ct_1, Fr_tmp[0]);

        Func.GetMCLZrRandomElement(Fr_tmp[1]);
        Mcl.mul(R.epk, mpk.mpk_FAME.g, Fr_tmp[1]);
        R_ = Arrays.copyOf(R_, Fr_tmp[0].serialize().length);
        SP.H2(Fr_tmp[2], Arrays.toString(R_));
        Mcl.add(Fr_tmp[2], Fr_tmp[0], Fr_tmp[2]);
        Mcl.mul(R.c, mpk.mpk_FAME.h, Fr_tmp[2]);
        SP.H2(Fr_tmp[2], String.format("%s|%s", R.epk, R.c));
        Mcl.mul(Fr_tmp[0], Fr_tmp[0], Fr_tmp[2]);
        Mcl.add(R.sigma, Fr_tmp[0], Fr_tmp[1]);
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, MasterPublicKey mpk, User owner, base.LSSS.MCL.Matrix MSP, Fr m) {
        H.owner_ID = new Fr[owner.ID.length];
        for (int i = 0;i < owner.ID.length; ++i) H.owner_ID[i] = new Fr(owner.ID[i]);

        Func.GetMCLZrRandomElement(Fr_tmp[3]);

        byte[] R_ = new byte[Fr_tmp[3].serialize().length / 2];
        SP.rand.nextBytes(R_);

        GenCipher(R, SP, mpk, owner, MSP, Fr_tmp[3], R_);
        SP.H2(Fr_tmp[0], Arrays.toString(R_));
        Mcl.mul(H.h_p, mpk.mpk_FAME.h, Fr_tmp[0]);

        Mcl.mul(H.b, H.h_p, m);
        Mcl.add(H.b, R.p, H.b);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, MasterPublicKey mpk, Fr m) {
        Mcl.mul(G1_tmp[0], H.h_p, m);
        Mcl.add(G1_tmp[0], R.p, G1_tmp[0]);
        Mcl.pairing(GT_tmp[0], R.ct_2, mpk.g_alpha);
        Mcl.pow(GT_tmp[0], GT_tmp[0], R.sigma);

        Mcl.pairing(GT_tmp[1], R.ct_1, R.epk);
        Mcl.pairing(GT_tmp[2], R.ct_3, mpk.mpk_FAME.g);
        SP.H2(Fr_tmp[0], R.epk + "|" + R.c);
        Mcl.pow(GT_tmp[2], GT_tmp[2], Fr_tmp[0]);
        Mcl.mul(GT_tmp[1], GT_tmp[1], GT_tmp[2]);
        return H.b.equals(G1_tmp[0]) && GT_tmp[0].equals(GT_tmp[1]);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, User moder, base.LSSS.MCL.Matrix MSP, Fr m, Fr m_p) {
        if(!Check(H, R, SP, mpk, m)) throw new RuntimeException("wrong hash");

        User moder_p = new User(moder);

        for(int i = moder_p.ID.length;i < H.owner_ID.length;++i)
            if(!moder_p.delegate(SP, mpk, msk, H.owner_ID[i])) throw new RuntimeException("delegate failed");

        Mcl.pairing(GT_tmp[0], R.ct_FAME.ct_0[2], moder_p.ssk.sk_1);
        Mcl.pairing(GT_tmp[1], R.ct_1, moder_p.ssk.sk_0_g[1]);
        Mcl.pairing(GT_tmp[2], R.ct_0_4, moder_p.ssk.sk_0_g[2]);
        Mcl.mul(GT_tmp[1], GT_tmp[1], GT_tmp[2]);
        Mcl.inv(GT_tmp[1], GT_tmp[1]);
        Mcl.mul(GT_tmp[0], GT_tmp[0], GT_tmp[1]);

        SP.H2(Fr_tmp[0], GT_tmp[0].toString());
        byte[] R_ = Fr_tmp[0].serialize();

        for(int i = 0;i < R_.length;++i) R_[i] ^= R.ct_p[i];

        boolean tag = true;
        for(int i = R_.length / 2;i < R_.length;++i) if(R_[i] != 0) {
            tag = false;
            break;
        }
        if(!tag) throw new RuntimeException("unable to adapt");

        R_ = Arrays.copyOf(R_, R_.length / 2);

        ABE.FAME.MCL_swap.PlainText pt_RABE = new ABE.FAME.MCL_swap.PlainText();
        FAME.Decrypt(pt_RABE, MSP, R.ct_FAME, moder_p.ssk.sk_FAME);

        Mcl.inv(pt_RABE.m, pt_RABE.m);
        byte[] r_ = pt_RABE.m.serialize();
        for(int i = 0;i < r_.length;++i) r_[i] ^= R.ct[i];
        Mcl.sub(Fr_tmp[3], m, m_p);
        SP.H2(Fr_tmp[1], Arrays.toString(R_));
        Mcl.div(Fr_tmp[1], Fr_tmp[1], moder_p.ssk.sk_ch);
        Mcl.mul(Fr_tmp[1], Fr_tmp[3], Fr_tmp[1]);
        try {
            Fr_tmp[3].deserialize(r_);
        } catch (Exception e) {
            Fr_tmp[3].setInt(0);
        }
        Mcl.add(Fr_tmp[3], Fr_tmp[3], Fr_tmp[1]);
        GenCipher(R_p, SP, mpk, moder_p, MSP, Fr_tmp[3], R_);
    }
}
