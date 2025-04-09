package ABE.FAME;

import base.GroupParam.PBC.Asymmetry;
import it.unisa.dia.gas.jpbc.Element;
import utils.BooleanFormulaParser;
import utils.Hash;

import java.util.HashMap;

/*
 * FAME: Fast Attribute-based Message Encryption
 * P6. 3 FAME: OUR CP-ABE SCHEME
 */

public class PBC {
    public static class PublicParam {
        public Asymmetry GP;

        public PublicParam(curve.PBC curve, boolean swap_G1G2) {
            GP = new Asymmetry(curve, swap_G1G2);
        }

        public PublicParam(Asymmetry GP) {
            this.GP = GP;
        }

        public Element H(String m) {
            return Hash.H_String_1_PBC_1(GP.G1, m);
        }
    }

    public static class MasterPublicKey {
        public Element g, h, H_1, H_2, T_1, T_2;
    }

    public static class MasterSecretKey {
        public Element b_1, b_2, a_1, a_2, g_d1, g_d2, g_d3;
    }

    public static class SecretKey {
        public HashMap<String, Integer> Attr2id;
        public BooleanFormulaParser.AttributeList S = new BooleanFormulaParser.AttributeList();
        public Element[][] sk_y;
        public Element[] sk_0 = new Element[3], sk_p = new Element[3];

        public void Init(BooleanFormulaParser.AttributeList S) {
            Attr2id = new HashMap<>();
            sk_y = new Element[S.attrs.size()][3];
            this.S.attrs.addAll(S.attrs);
        }

        public void CopyFrom(SecretKey sk) {
            Attr2id = new HashMap<>(sk.Attr2id);
            S.CopyFrom(sk.S);
            sk_y = new Element[sk.sk_y.length][sk.sk_y[0].length];
            for (int i = 0; i < sk.sk_y.length; i++) System.arraycopy(sk.sk_y[i], 0, sk_y[i], 0, sk.sk_y[0].length);
            System.arraycopy(sk.sk_0, 0, sk_0, 0, sk.sk_0.length);
            System.arraycopy(sk.sk_p, 0, sk_p, 0, sk.sk_p.length);
        }
    }

    public static class CipherText {
        public Element[] ct_0 = new Element[3];
        public Element[][] ct;
        public Element ct_p;

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
            return ct_p.isEqual(CT_p.ct_p);
        }
    }

    public static class PlainText {
        public Element m;

        public PlainText() {}

        public PlainText(Element m) {
            this.m = m;
        }

        public boolean isEqual(PlainText p) {
            return m.isEqual(p.m);
        }
    }

    public void SetUp(MasterPublicKey mpk, MasterSecretKey msk, PublicParam SP) {
        Element d_1 = SP.GP.GetZrElement();
        Element d_2 = SP.GP.GetZrElement();
        Element d_3 = SP.GP.GetZrElement();
        SetUp(mpk, msk, SP, d_1, d_2, d_3, SP.GP.Zr.newOneElement().getImmutable());
    }

    public void SetUp(MasterPublicKey mpk, MasterSecretKey msk, PublicParam SP, Element d_1, Element d_2, Element d_3, Element alpha) {
        mpk.h = SP.GP.GetG2Element();

        mpk.g = SP.GP.GetG1Element();

        Element egh = SP.GP.pairing(mpk.g, mpk.h);

        msk.a_1 = SP.GP.GetZrElement();
        msk.a_2 = SP.GP.GetZrElement();
        msk.b_1 = SP.GP.GetZrElement();
        msk.b_2 = SP.GP.GetZrElement();

        mpk.H_1 = mpk.h.powZn(msk.a_1).getImmutable();
        mpk.H_2 = mpk.h.powZn(msk.a_2).getImmutable();
        mpk.T_1 = egh.powZn(d_1.mul(msk.a_1).add(d_3.div(alpha))).getImmutable();
        mpk.T_2 = egh.powZn(d_2.mul(msk.a_2).add(d_3.div(alpha))).getImmutable();

        msk.g_d1 = mpk.g.powZn(d_1).getImmutable();
        msk.g_d2 = mpk.g.powZn(d_2).getImmutable();
        msk.g_d3 = mpk.g.powZn(d_3).getImmutable();
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, BooleanFormulaParser.AttributeList S) {
        Element r_1 = SP.GP.GetZrElement(), r_2 = SP.GP.GetZrElement();
        KeyGen(sk, SP, mpk, msk, S, r_1, r_2, SP.GP.Zr.newOneElement().getImmutable());
    }

    public void KeyGen(SecretKey sk, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, BooleanFormulaParser.AttributeList S, Element r_1, Element r_2, Element alpha) {
        sk.Init(S);
        Element b1r1a1 = msk.b_1.mul(r_1).getImmutable();
        sk.sk_0[0] = mpk.h.powZn(b1r1a1).getImmutable();
        Element b1r1a2 = b1r1a1.div(msk.a_2).getImmutable();
        b1r1a1 = b1r1a1.div(msk.a_1).getImmutable();
        Element b2r2a1 = msk.b_2.mul(r_2).getImmutable();
        sk.sk_0[1] = mpk.h.powZn(b2r2a1).getImmutable();
        Element b2r2a2 = b2r2a1.div(msk.a_2).getImmutable();
        b2r2a1 = b2r2a1.div(msk.a_1).getImmutable();
        sk.sk_0[2] = mpk.h.powZn(r_1.add(r_2).div(alpha)).getImmutable();

        Element alpha_a_1 = alpha.mul(msk.a_1).getImmutable();
        Element alpha_a_2 = alpha.mul(msk.a_2).getImmutable();

        int i = 0;
        for(String y : S.attrs) {
            sk.Attr2id.put(y, i);
            Element sigma_y = SP.GP.GetZrElement();
            sk.sk_y[i][0] = SP.H(y + "11").powZn(b1r1a1)
                    .mul(SP.H(y + "21").powZn(b2r2a1))
                    .mul(SP.H(y + "31").powZn(r_1.add(r_2).div(alpha_a_1))).mul(mpk.g.powZn(sigma_y.div(alpha_a_1))).getImmutable();

            sk.sk_y[i][1] = SP.H(y + "12").powZn(b1r1a2)
                    .mul(SP.H(y + "22").powZn(b2r2a2))
                    .mul(SP.H(y + "32").powZn(r_1.add(r_2).div(alpha_a_2))).mul(mpk.g.powZn(sigma_y.div(alpha_a_2))).getImmutable();
            sk.sk_y[i][2] = mpk.g.powZn(sigma_y).invert().getImmutable();
            ++i;
        }

        Element sigma_p = SP.GP.GetZrElement();

        sk.sk_p[0] = msk.g_d1.mul(SP.H("0111").powZn(b1r1a1))
                .mul(SP.H("0121").powZn(b2r2a1))
                .mul(SP.H("0131").powZn(r_1.add(r_2).div(alpha_a_1))).mul(mpk.g.powZn(sigma_p.div(alpha_a_1))).getImmutable();

        sk.sk_p[1] = msk.g_d2.mul(SP.H("0112").powZn(b1r1a2))
                .mul(SP.H("0122").powZn(b2r2a2))
                .mul(SP.H("0132").powZn(r_1.add(r_2).div(alpha_a_2))).mul(mpk.g.powZn(sigma_p.div(alpha_a_2))).getImmutable();

        sk.sk_p[2] = msk.g_d3.div(mpk.g.powZn(sigma_p)).getImmutable();
    }

    public void Encrypt(CipherText CT, PublicParam SP, MasterPublicKey mpk, base.LSSS.PBC.Matrix MSP, PlainText PT) {
        Element s_1 = SP.GP.GetZrElement();
        Element s_2 = SP.GP.GetZrElement();
        Encrypt(CT, SP, mpk, MSP, PT, s_1, s_2);
    }

    public void Encrypt(CipherText CT, PublicParam SP, MasterPublicKey mpk, base.LSSS.PBC.Matrix MSP, PlainText PT, Element s_1, Element s_2) {
        CT.ct_0[0] = mpk.H_1.powZn(s_1).getImmutable();
        CT.ct_0[1] = mpk.H_2.powZn(s_2).getImmutable();
        CT.ct_0[2] = mpk.h.powZn(s_1.add(s_2)).getImmutable();

        CT.ct_p = mpk.T_1.powZn(s_1).mul(mpk.T_2.powZn(s_2)).mul(PT.m).getImmutable();

        int n1 = MSP.M.length, n2 = MSP.M[0].length;
        CT.ct = new Element[n1][3];

        Element[][] Hjl = new Element[n2][3];
        for(int l = 1;l <= 3;++l) {
            for (int j = 1; j <= n2; ++j) Hjl[j - 1][l - 1] = SP.H(String.format("0%d%d1", j, l)).powZn(s_1)
                    .mul(SP.H(String.format("0%d%d2", j, l)).powZn(s_2));
        }

        for(int i = 0; i < n1; ++i) {
            for(int l = 1;l <= 3;++l) {
                CT.ct[i][l - 1] = SP.H(String.format("%s%d1", MSP.policy[i], l)).powZn(s_1).mul(SP.H(String.format("%s%d2", MSP.policy[i], l)).powZn(s_2)).getImmutable();
                for(int j = 1; j <= n2; ++j) CT.ct[i][l - 1] = CT.ct[i][l - 1].mul(Hjl[j - 1][l - 1].powZn(MSP.M[i][j - 1])).getImmutable();
            }
        }
    }

    public void Decrypt(PlainText PT, PublicParam SP, base.LSSS.PBC.Matrix MSP, CipherText CT, SecretKey sk) {
        base.LSSS.PBC.Matrix.Vector gamma = new base.LSSS.PBC.Matrix.Vector();
        MSP.Solve(gamma, sk.S);
        Element num = CT.ct_p, tmp;
        for(int t = 0;t < 3;++t) {
            tmp = SP.GP.G1.newOneElement().getImmutable();
            for(int i = 0;i < CT.ct.length;++i) tmp = tmp.mul(CT.ct[i][t].powZn(gamma.v[i])).getImmutable();
            num = num.mul(SP.GP.pairing(tmp, sk.sk_0[t]));
        }
        Element den = SP.GP.GT.newOneElement().getImmutable();
        for(int t = 0;t < 3;++t) {
            tmp = sk.sk_p[t];
            for(int i = 0;i < CT.ct.length;++i) {
                if(sk.Attr2id.get(MSP.policy[i]) == null) continue;
                tmp = tmp.mul(sk.sk_y[sk.Attr2id.get(MSP.policy[i])][t].powZn(gamma.v[i])).getImmutable();
            }
            den = den.mul(SP.GP.pairing(tmp, CT.ct_0[t]));
        }
        PT.m = num.div(den).getImmutable();
    }
}
