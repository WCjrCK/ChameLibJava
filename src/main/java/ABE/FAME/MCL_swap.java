package ABE.FAME;

import com.herumi.mcl.*;
import utils.BooleanFormulaParser;
import utils.Func;
import utils.Hash;

import java.util.HashMap;

/*
 * FAME: Fast Attribute-based Message Encryption
 * P6. 3 FAME: OUR CP-ABE SCHEME
 */

public class MCL_swap {
    public static class PublicParam {
        public void H(G2 res, String m) {
            Hash.H_MCL_G2_1(res, m);
        }
    }

    public static class MasterPublicKey {
        public G2 g = new G2();
        public G1 h = new G1(), H_1 = new G1(), H_2 = new G1();
        public GT T_1 = new GT(), T_2 = new GT();
    }

    public static class MasterSecretKey {
        public G2 g_d1 = new G2(), g_d2 = new G2(), g_d3 = new G2();
        public Fr a_1 = new Fr(), a_2 = new Fr(), b_1 = new Fr(), b_2 = new Fr();
    }

    public static class SecretKey {
        public HashMap<String, Integer> Attr2id;
        public BooleanFormulaParser.AttributeList S = new BooleanFormulaParser.AttributeList();
        public G2[][] sk_y;
        public G2[] sk_p = new G2[]{new G2(), new G2(), new G2()};
        public G1[] sk_0 = new G1[]{new G1(), new G1(), new G1()};

        public void Init(BooleanFormulaParser.AttributeList S) {
            Attr2id = new HashMap<>();
            sk_y = new G2[S.attrs.size()][3];
            for (int i = 0; i < S.attrs.size(); i++) for (int j = 0;j < 3;++j) sk_y[i][j] = new G2();
            this.S.attrs.addAll(S.attrs);
        }

        public void CopyFrom(SecretKey sk) {
            Attr2id = new HashMap<>(sk.Attr2id);
            S.CopyFrom(sk.S);
            sk_y = new G2[sk.sk_y.length][sk.sk_y[0].length];
            for (int i = 0; i < sk.sk_y.length; i++) for (int j = 0;j < sk.sk_y[i].length; ++j) {
                sk_y[i][j] = new G2();
                Mcl.neg(sk_y[i][j], sk.sk_y[i][j]);
                Mcl.neg(sk_y[i][j], sk_y[i][j]);
            }
            for (int i = 0; i < sk.sk_0.length; i++) {
                Mcl.neg(sk_0[i], sk.sk_0[i]);
                Mcl.neg(sk_0[i], sk_0[i]);
            }
            for (int i = 0; i < sk.sk_p.length; i++) {
                Mcl.neg(sk_p[i], sk.sk_p[i]);
                Mcl.neg(sk_p[i], sk_p[i]);
            }
        }
    }

    public static class CipherText {
        public G1[] ct_0 = new G1[]{new G1(), new G1(), new G1()};
        public G2[][] ct;
        public GT ct_p = new GT();

        public boolean isEqual(CipherText CT_p) {
            if(ct_0.length != CT_p.ct_0.length) return false;
            if(ct.length != CT_p.ct.length) return false;
            if(ct[0].length != CT_p.ct[0].length) return false;
            for(int i = 0; i < ct_0.length; ++i) {
                if(!ct_0[i].equals(CT_p.ct_0[i])) return false;
            }
            for(int i = 0; i < ct.length; ++i) {
                for(int j = 0; j < ct[i].length; ++j) {
                    if(!ct[i][j].equals(CT_p.ct[i][j])) return false;
                }
            }
            return ct_p.equals(CT_p.ct_p);
        }
    }

    public static class PlainText {
        public GT m = new GT();

        public PlainText() {
            Func.GetMCLGTRandomElement(m);
        }

        public PlainText(GT m) {
            this.m = m;
        }

        public boolean isEqual(PlainText p) {
            return m.equals(p.m);
        }
    }

    private final G2[] G2_tmp = new G2[]{new G2(), new G2()};
    private final GT[] GT_tmp = new GT[]{new GT(), new GT()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr(), new Fr(), new Fr(), new Fr(), new Fr(), new Fr(), new Fr(), new Fr(), new Fr(), new Fr(), new Fr()};

    public void SetUp(MasterPublicKey mpk, MasterSecretKey msk) {
        Func.GetMCLZrRandomElement(Fr_tmp[2]);
        Func.GetMCLZrRandomElement(Fr_tmp[3]);
        Func.GetMCLZrRandomElement(Fr_tmp[4]);
        Fr_tmp[5].setInt(1);
        SetUp(mpk, msk, Fr_tmp[2], Fr_tmp[3], Fr_tmp[4], Fr_tmp[5]);
    }

    public void SetUp(MasterPublicKey mpk, MasterSecretKey msk, Fr d_1, Fr d_2, Fr d_3, Fr alpha) {
        Func.GetMCLG1RandomElement(mpk.h);
        Func.GetMCLG2RandomElement(mpk.g);

        Mcl.pairing(GT_tmp[0], mpk.h, mpk.g);

        Func.GetMCLZrRandomElement(msk.a_1);
        Func.GetMCLZrRandomElement(msk.a_2);
        Func.GetMCLZrRandomElement(msk.b_1);
        Func.GetMCLZrRandomElement(msk.b_2);

        Mcl.mul(mpk.H_1, mpk.h, msk.a_1);
        Mcl.mul(mpk.H_2, mpk.h, msk.a_2);

        Mcl.mul(Fr_tmp[0], d_1, msk.a_1);
        Mcl.div(Fr_tmp[1], d_3, alpha);
        Mcl.add(Fr_tmp[0], Fr_tmp[0], Fr_tmp[1]);
        Mcl.pow(mpk.T_1, GT_tmp[0], Fr_tmp[0]);
        Mcl.mul(Fr_tmp[0], d_2, msk.a_2);
        Mcl.add(Fr_tmp[0], Fr_tmp[0], Fr_tmp[1]);
        Mcl.pow(mpk.T_2, GT_tmp[0], Fr_tmp[0]);

        Mcl.mul(msk.g_d1, mpk.g, d_1);
        Mcl.mul(msk.g_d2, mpk.g, d_2);
        Mcl.mul(msk.g_d3, mpk.g, d_3);
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, BooleanFormulaParser.AttributeList S) {
        Func.GetMCLZrRandomElement(Fr_tmp[9]);
        Func.GetMCLZrRandomElement(Fr_tmp[10]);
        Fr_tmp[11].setInt(1);
        KeyGen(sk, SP, mpk, msk, S, Fr_tmp[9], Fr_tmp[10], Fr_tmp[11]);
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, BooleanFormulaParser.AttributeList S, Fr r_1, Fr r_2, Fr alpha) {
        sk.Init(S);

        Mcl.mul(Fr_tmp[0], msk.b_1, r_1);
        Mcl.mul(sk.sk_0[0], mpk.h, Fr_tmp[0]);
        Mcl.div(Fr_tmp[1], Fr_tmp[0], msk.a_2);
        Mcl.div(Fr_tmp[0], Fr_tmp[0], msk.a_1);

        Mcl.mul(Fr_tmp[2], msk.b_2, r_2);
        Mcl.mul(sk.sk_0[1], mpk.h, Fr_tmp[2]);
        Mcl.div(Fr_tmp[3], Fr_tmp[2], msk.a_2);
        Mcl.div(Fr_tmp[2], Fr_tmp[2], msk.a_1);

        Mcl.add(Fr_tmp[4], r_1, r_2);
        Mcl.div(Fr_tmp[5], Fr_tmp[4], alpha);
        Mcl.mul(sk.sk_0[2], mpk.h, Fr_tmp[5]);

        Mcl.mul(Fr_tmp[5], alpha, msk.a_1);
        Mcl.mul(Fr_tmp[6], alpha, msk.a_2);

        Mcl.div(Fr_tmp[8], Fr_tmp[4], Fr_tmp[5]);
        Mcl.div(Fr_tmp[10], Fr_tmp[4], Fr_tmp[6]);

        int i = 0;
        for(String y : S.attrs) {
            sk.Attr2id.put(y, i);
            Func.GetMCLZrRandomElement(Fr_tmp[7]);
            Mcl.div(Fr_tmp[9], Fr_tmp[7], Fr_tmp[5]);
            Mcl.div(Fr_tmp[11], Fr_tmp[7], Fr_tmp[6]);

            SP.H(sk.sk_y[i][0], y + "11");
            Mcl.mul(sk.sk_y[i][0], sk.sk_y[i][0], Fr_tmp[0]);
            SP.H(G2_tmp[0], y + "21");
            Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[2]);
            Mcl.add(sk.sk_y[i][0], sk.sk_y[i][0], G2_tmp[0]);
            SP.H(G2_tmp[0], y + "31");
            Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[8]);
            Mcl.add(sk.sk_y[i][0], sk.sk_y[i][0], G2_tmp[0]);
            Mcl.mul(G2_tmp[0], mpk.g, Fr_tmp[9]);
            Mcl.add(sk.sk_y[i][0], sk.sk_y[i][0], G2_tmp[0]);

            SP.H(sk.sk_y[i][1], y + "12");
            Mcl.mul(sk.sk_y[i][1], sk.sk_y[i][1], Fr_tmp[1]);
            SP.H(G2_tmp[0], y + "22");
            Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[3]);
            Mcl.add(sk.sk_y[i][1], sk.sk_y[i][1], G2_tmp[0]);
            SP.H(G2_tmp[0], y + "32");
            Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[10]);
            Mcl.add(sk.sk_y[i][1], sk.sk_y[i][1], G2_tmp[0]);
            Mcl.mul(G2_tmp[0], mpk.g, Fr_tmp[11]);
            Mcl.add(sk.sk_y[i][1], sk.sk_y[i][1], G2_tmp[0]);

            Mcl.neg(Fr_tmp[7], Fr_tmp[7]);
            Mcl.mul(sk.sk_y[i][2], mpk.g, Fr_tmp[7]);
            ++i;
        }

        Func.GetMCLZrRandomElement(Fr_tmp[7]);
        Mcl.div(Fr_tmp[9], Fr_tmp[7], Fr_tmp[5]);
        Mcl.div(Fr_tmp[11], Fr_tmp[7], Fr_tmp[6]);

        SP.H(sk.sk_p[0], "0111");
        Mcl.mul(sk.sk_p[0], sk.sk_p[0], Fr_tmp[0]);
        SP.H(G2_tmp[0], "0121");
        Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[2]);
        Mcl.add(sk.sk_p[0], sk.sk_p[0], G2_tmp[0]);
        SP.H(G2_tmp[0], "0131");
        Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[8]);
        Mcl.add(sk.sk_p[0], sk.sk_p[0], G2_tmp[0]);
        Mcl.mul(G2_tmp[0], mpk.g, Fr_tmp[9]);
        Mcl.add(sk.sk_p[0], sk.sk_p[0], G2_tmp[0]);
        Mcl.add(sk.sk_p[0], msk.g_d1, sk.sk_p[0]);

        SP.H(sk.sk_p[1], "0112");
        Mcl.mul(sk.sk_p[1], sk.sk_p[1], Fr_tmp[1]);
        SP.H(G2_tmp[0], "0122");
        Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[3]);
        Mcl.add(sk.sk_p[1], sk.sk_p[1], G2_tmp[0]);
        SP.H(G2_tmp[0], "0132");
        Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[10]);
        Mcl.add(sk.sk_p[1], sk.sk_p[1], G2_tmp[0]);
        Mcl.mul(G2_tmp[0], mpk.g, Fr_tmp[11]);
        Mcl.add(sk.sk_p[1], sk.sk_p[1], G2_tmp[0]);
        Mcl.add(sk.sk_p[1], msk.g_d2, sk.sk_p[1]);

        Mcl.mul(sk.sk_p[2], mpk.g, Fr_tmp[7]);
        Mcl.sub(sk.sk_p[2], msk.g_d3, sk.sk_p[2]);
    }

    public void Encrypt(CipherText CT, PublicParam SP, MasterPublicKey mpk, base.LSSS.MCL.Matrix MSP, PlainText PT) {
        Func.GetMCLZrRandomElement(Fr_tmp[1]);
        Func.GetMCLZrRandomElement(Fr_tmp[2]);
        Encrypt(CT, SP, mpk, MSP, PT, Fr_tmp[1], Fr_tmp[2]);
    }

    public void Encrypt(CipherText CT, PublicParam SP, MasterPublicKey mpk, base.LSSS.MCL.Matrix MSP, PlainText PT, Fr s_1, Fr s_2) {
        Mcl.mul(CT.ct_0[0], mpk.H_1, s_1);
        Mcl.mul(CT.ct_0[1], mpk.H_2, s_2);
        Mcl.add(Fr_tmp[0], s_1, s_2);
        Mcl.mul(CT.ct_0[2], mpk.h, Fr_tmp[0]);

        Mcl.pow(CT.ct_p, mpk.T_1, s_1);
        Mcl.pow(GT_tmp[0], mpk.T_2, s_2);
        Mcl.mul(CT.ct_p, CT.ct_p, GT_tmp[0]);
         Mcl.mul(CT.ct_p, CT.ct_p, PT.m);

        int n1 = MSP.M.length, n2 = MSP.M[0].length;
        CT.ct = new G2[n1][3];
        for (int i = 0;i < n1;i++) for (int j = 0;j < 3;j++) CT.ct[i][j] = new G2();

        G2[][] Hjl = new G2[n2][3];
        for(int l = 1;l <= 3;++l) {
            for (int j = 1; j <= n2; ++j) {
                Hjl[j - 1][l - 1] = new G2();
                SP.H(Hjl[j - 1][l - 1], String.format("0%d%d1", j, l));
                Mcl.mul(Hjl[j - 1][l - 1], Hjl[j - 1][l - 1], s_1);
                SP.H(G2_tmp[0], String.format("0%d%d2", j, l));
                Mcl.mul(G2_tmp[0], G2_tmp[0], s_2);
                Mcl.add(Hjl[j - 1][l - 1], Hjl[j - 1][l - 1], G2_tmp[0]);
            }
        }

        for(int i = 0; i < n1; ++i) {
            for(int l = 1;l <= 3;++l) {
                SP.H(CT.ct[i][l - 1], String.format("%s%d1", MSP.policy[i], l));
                Mcl.mul(CT.ct[i][l - 1], CT.ct[i][l - 1], s_1);
                SP.H(G2_tmp[0], String.format("%s%d2", MSP.policy[i], l));
                Mcl.mul(G2_tmp[0], G2_tmp[0], s_2);
                Mcl.add(CT.ct[i][l - 1], CT.ct[i][l - 1], G2_tmp[0]);

                for(int j = 1; j <= n2; ++j) {
                    Mcl.mul(G2_tmp[0], Hjl[j - 1][l - 1], MSP.M[i][j - 1]);
                    Mcl.add(CT.ct[i][l - 1], CT.ct[i][l - 1], G2_tmp[0]);
                }
            }
        }
    }

    public void Decrypt(PlainText PT, base.LSSS.MCL.Matrix MSP, CipherText CT, SecretKey sk) {
        base.LSSS.MCL.Matrix.Vector gamma = new base.LSSS.MCL.Matrix.Vector();
        MSP.Solve(gamma, sk.S);

        for(int t = 0;t < 3;++t) {
            boolean fir = true;
            for(int i = 0;i < CT.ct.length;++i) {
                if(sk.Attr2id.get(MSP.policy[i]) == null) continue;
                if (fir) {
                    fir = false;
                    Mcl.mul(G2_tmp[0], sk.sk_y[sk.Attr2id.get(MSP.policy[i])][t], gamma.v[i]);
                } else {
                    Mcl.mul(G2_tmp[1], sk.sk_y[sk.Attr2id.get(MSP.policy[i])][t], gamma.v[i]);
                    Mcl.add(G2_tmp[0], G2_tmp[0], G2_tmp[1]);
                }
            }
            Mcl.add(G2_tmp[0], sk.sk_p[t], G2_tmp[0]);
            if (t == 0) Mcl.pairing(GT_tmp[0], CT.ct_0[t], G2_tmp[0]);
            else {
                Mcl.pairing(GT_tmp[1], CT.ct_0[t], G2_tmp[0]);
                Mcl.mul(GT_tmp[0], GT_tmp[0], GT_tmp[1]);
            }
        }

        Mcl.inv(PT.m, GT_tmp[0]);

        for(int t = 0;t < 3;++t) {
            boolean fir = true;
            for(int i = 0;i < CT.ct.length;++i) {
                if (fir) {
                    Mcl.mul(G2_tmp[0], CT.ct[i][t], gamma.v[i]);
                    fir = false;
                } else {
                    Mcl.mul(G2_tmp[1], CT.ct[i][t], gamma.v[i]);
                    Mcl.add(G2_tmp[0], G2_tmp[0], G2_tmp[1]);
                }
            }
            if (t == 0) Mcl.pairing(GT_tmp[0], sk.sk_0[t], G2_tmp[0]);
            else {
                Mcl.pairing(GT_tmp[1], sk.sk_0[t], G2_tmp[0]);
                Mcl.mul(GT_tmp[0], GT_tmp[0], GT_tmp[1]);
            }
        }

        Mcl.mul(GT_tmp[0], CT.ct_p, GT_tmp[0]);

        Mcl.mul(PT.m, GT_tmp[0], PT.m);
    }
}
