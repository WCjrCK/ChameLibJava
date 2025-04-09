package ABE.RABE;

import com.herumi.mcl.*;
import utils.BooleanFormulaParser;
import utils.Func;

import java.util.HashMap;

/*
 * Revocable Policy-Based Chameleon Hash
 * P12. 5.1 Proposed RABE
 */

public class MCL_swap {
    public enum TYPE {
        /*
         * Revocable Policy-Based Chameleon Hash
         * P12. 5.1 Proposed RABE
         */
        XNM_2021,

        /*
         * Revocable Policy-Based ChameleonHash for Blockchain Rewriting
         * P7. 4.1. The proposed RABE scheme
         */
        TMM_2022
    }

    public static class PublicParam {
        public ABE.FAME.MCL_swap.PublicParam pp_FAME = new ABE.FAME.MCL_swap.PublicParam();
        public TYPE type;

        public PublicParam(TYPE t) {
            type = t;
        }

        public void H(G2 res, String m) {
            if(type == TYPE.XNM_2021) pp_FAME.H(res, "1" + m);
            else if(type == TYPE.TMM_2022) pp_FAME.H(res, m);
            else pp_FAME.H(res, m);
        }
    }

    public static class MasterPublicKey {
        public ABE.FAME.MCL_swap.MasterPublicKey mpk_FAME = new ABE.FAME.MCL_swap.MasterPublicKey();
    }

    public static class MasterSecretKey {
        public ABE.FAME.MCL_swap.MasterSecretKey msk_FAME = new ABE.FAME.MCL_swap.MasterSecretKey();
    }

    public static class SecretKey {
        public ABE.FAME.MCL_swap.SecretKey sk_FAME = new ABE.FAME.MCL_swap.SecretKey();
        public HashMap<Integer, G2> sk_theta = new HashMap<>();
        int node_id;
    }

    public static class UpdateKey {
        int t;
        public HashMap<Integer, G2> ku_theta_G2 = new HashMap<>();
        public HashMap<Integer, G1> ku_theta_G1 = new HashMap<>();

        public void AddKey(int theta, G2 k_u_theta_0, G1 k_u_theta_1) {
            G2 tmp_g1 = new G2();
            Mcl.neg(tmp_g1, k_u_theta_0);
            Mcl.neg(tmp_g1, tmp_g1);
            ku_theta_G2.put(theta, tmp_g1);
            G1 tmp_g2 = new G1();
            Mcl.neg(tmp_g2, k_u_theta_1);
            Mcl.neg(tmp_g2, tmp_g2);
            ku_theta_G1.put(theta, tmp_g2);
        }
    }

    public static class DecryptKey {
        public int node_id, t;
        public ABE.FAME.MCL_swap.SecretKey sk_FAME = new ABE.FAME.MCL_swap.SecretKey();
        public G1 sk_0_4 = new G1();

        public void CopyFrom(SecretKey sk) {
            sk_FAME.CopyFrom(sk.sk_FAME);
        }
    }

    public static class CipherText {
        public ABE.FAME.MCL_swap.CipherText ct_FAME = new ABE.FAME.MCL_swap.CipherText();
        byte[] ct_TMM_2022;
        G2 ct_0_4 = new G2();

        public boolean isEqual(CipherText CT_p) {
            return ct_FAME.isEqual(CT_p.ct_FAME) && ct_0_4.equals(CT_p.ct_0_4);
        }
    }

    public static class PlainText {
        public GT m = new GT();

        public PlainText() {}

        public PlainText(GT m) {
            this.m = m;
        }

        public boolean isEqual(PlainText p) {
            return m.equals(p.m);
        }
    }

    public static class PlainTextFr {
        public Fr m = new Fr();

        public PlainTextFr() {}

        public PlainTextFr(Fr m) {
            this.m = m;
        }

        public boolean isEqual(MCL.PlainText p) {
            return m.equals(p.m);
        }
    }

    public ABE.FAME.MCL_swap FAME = new ABE.FAME.MCL_swap();

    private final G2[] G2_tmp = new G2[]{new G2()};
    private final G1[] G1_tmp = new G1[]{new G1()};
    private final GT[] GT_tmp = new GT[]{new GT(), new GT()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr(), new Fr()};

    public void SetUp(MasterPublicKey mpk, MasterSecretKey msk) {
        FAME.SetUp(mpk.mpk_FAME, msk.msk_FAME);
    }

    public void KeyGen(SecretKey sk, base.BinaryTree.MCL_G2 st, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, BooleanFormulaParser.AttributeList S, G2 id) {
        FAME.KeyGen(sk.sk_FAME, SP.pp_FAME, mpk.mpk_FAME, msk.msk_FAME, S);

        int theta = st.Pick(id);
        sk.node_id = theta;
        if(!st.tag_g.get(theta)) st.Setg(theta);
        G2 tmp_g1 = new G2();
        Mcl.sub(tmp_g1, sk.sk_FAME.sk_p[2], st.g_theta[theta]);
        sk.sk_theta.put(theta, tmp_g1);
        while(theta != 0) {
            theta = st.GetFNodeId(theta);
            if(!st.tag_g.get(theta)) st.Setg(theta);
            G2 tmp_g2 = new G2();
            Mcl.sub(tmp_g2, sk.sk_FAME.sk_p[2], st.g_theta[theta]);
            sk.sk_theta.put(theta, tmp_g2);
        }
        // hide g^d3g^{-rho_p}/g_theta
        Func.GetMCLG2RandomElement(sk.sk_FAME.sk_p[2]);
    }

    public void UpdateKeyGen(UpdateKey ku, PublicParam SP, MasterPublicKey mpk, base.BinaryTree.MCL_G2 st, base.BinaryTree.MCL_G2.RevokeList rl, int t) {
        st.GetUpdateKeyNode(rl, t);
        ku.t = t;
        for(int theta = 0;theta < st.g_theta.length;++theta) {
            if(st.tag.get(theta) && st.tag_g.get(theta)) {
                Func.GetMCLZrRandomElement(Fr_tmp[0]);
                SP.H(G2_tmp[0], String.valueOf(t));
                Mcl.mul(G2_tmp[0], G2_tmp[0], Fr_tmp[0]);
                Mcl.add(G2_tmp[0], st.g_theta[theta], G2_tmp[0]);
                Mcl.mul(G1_tmp[0], mpk.mpk_FAME.h, Fr_tmp[0]);
                ku.AddKey(theta, G2_tmp[0], G1_tmp[0]);
            }
        }
    }

    public void DecryptKeyGen(DecryptKey dk, PublicParam SP, MasterPublicKey mpk, SecretKey sk, UpdateKey ku, base.BinaryTree.MCL_G2 st, base.BinaryTree.MCL_G2.RevokeList rl) {
        st.GetUpdateKeyNode(rl, ku.t);

        int node_id = sk.node_id, theta = -1;
        if(st.tag.get(node_id)) theta = node_id;
        while(node_id != 0 && theta == -1) {
            node_id = st.GetFNodeId(node_id);
            if(st.tag.get(node_id)) theta = node_id;
        }

        if(theta != -1) {
            dk.CopyFrom(sk);
            dk.t = ku.t;
            dk.node_id = sk.node_id;
            G2 ku_theta_0 = ku.ku_theta_G2.get(theta);
            G1 ku_theta_1 = ku.ku_theta_G1.get(theta);
            if(SP.type == TYPE.XNM_2021) {
                Func.GetMCLZrRandomElement(Fr_tmp[0]);
                SP.H(dk.sk_FAME.sk_p[2], String.valueOf(dk.t));
                Mcl.mul(dk.sk_FAME.sk_p[2], dk.sk_FAME.sk_p[2], Fr_tmp[0]);
                Mcl.add(dk.sk_FAME.sk_p[2], ku_theta_0, dk.sk_FAME.sk_p[2]);
                Mcl.add(dk.sk_FAME.sk_p[2], sk.sk_theta.get(theta), dk.sk_FAME.sk_p[2]);
                Mcl.mul(dk.sk_0_4, mpk.mpk_FAME.h, Fr_tmp[0]);
                Mcl.add(dk.sk_0_4, ku_theta_1, dk.sk_0_4);
            } else if(SP.type == TYPE.TMM_2022) {
                Mcl.add(dk.sk_FAME.sk_p[2], sk.sk_theta.get(theta), ku_theta_0);
                Mcl.neg(dk.sk_0_4, ku_theta_1);
                Mcl.neg(dk.sk_0_4, dk.sk_0_4);
            }
        }
    }

    public void Encrypt(CipherText CT, PublicParam SP, MasterPublicKey mpk, base.LSSS.MCL.Matrix MSP, PlainText PT, int t) {
        Func.GetMCLZrRandomElement(Fr_tmp[1]);
        Func.GetMCLZrRandomElement(Fr_tmp[2]);
        Encrypt(CT, SP, mpk, MSP, PT, t, Fr_tmp[1], Fr_tmp[2]);
    }

    public void Encrypt(CipherText CT, PublicParam SP, MasterPublicKey mpk, base.LSSS.MCL.Matrix MSP, PlainText PT, int t, Fr s_1, Fr s_2) {
        Mcl.add(Fr_tmp[0], s_1, s_2);
        SP.H(CT.ct_0_4, String.valueOf(t));
        Mcl.mul(CT.ct_0_4, CT.ct_0_4, Fr_tmp[0]);
        if(SP.type == TYPE.XNM_2021) {
            FAME.Encrypt(CT.ct_FAME, SP.pp_FAME, mpk.mpk_FAME, MSP, new ABE.FAME.MCL_swap.PlainText(PT.m), s_1, s_2);
        } else if(SP.type == TYPE.TMM_2022) {
            Func.GetMCLGTRandomElement(GT_tmp[0]);
            Mcl.inv(GT_tmp[1], GT_tmp[0]);
            Mcl.mul(GT_tmp[0], GT_tmp[1], GT_tmp[0]);
            FAME.Encrypt(CT.ct_FAME, SP.pp_FAME, mpk.mpk_FAME, MSP, new ABE.FAME.MCL_swap.PlainText(GT_tmp[0]), s_1, s_2);
            CT.ct_TMM_2022 = CT.ct_FAME.ct_p.serialize();
            Mcl.inv(CT.ct_FAME.ct_p, GT_tmp[0]);

            byte[] tmp = PT.m.serialize();
            for(int i = 0;i < tmp.length;++i) CT.ct_TMM_2022[i] ^= tmp[i];
        }
    }

    public void EncryptFr(CipherText CT, PublicParam SP, MasterPublicKey mpk, base.LSSS.MCL.Matrix MSP, MCL.PlainTextFr PT, int t) {
        Func.GetMCLZrRandomElement(Fr_tmp[1]);
        Func.GetMCLZrRandomElement(Fr_tmp[2]);
        EncryptFr(CT, SP, mpk, MSP, PT, t, Fr_tmp[1], Fr_tmp[2]);
    }

    public void EncryptFr(CipherText CT, PublicParam SP, MasterPublicKey mpk, base.LSSS.MCL.Matrix MSP, MCL.PlainTextFr PT, int t, Fr s_1, Fr s_2) {
        Mcl.add(Fr_tmp[0], s_1, s_2);
        SP.H(CT.ct_0_4, String.valueOf(t));
        Mcl.mul(CT.ct_0_4, CT.ct_0_4, Fr_tmp[0]);
        Func.GetMCLGTRandomElement(GT_tmp[0]);
        Mcl.inv(GT_tmp[1], GT_tmp[0]);
        Mcl.mul(GT_tmp[0], GT_tmp[1], GT_tmp[0]);
        FAME.Encrypt(CT.ct_FAME, SP.pp_FAME, mpk.mpk_FAME, MSP, new ABE.FAME.MCL_swap.PlainText(GT_tmp[0]), s_1, s_2);
        CT.ct_TMM_2022 = CT.ct_FAME.ct_p.serialize();
        Mcl.inv(CT.ct_FAME.ct_p, GT_tmp[0]);

        byte[] tmp = PT.m.serialize();
        for(int i = 0;i < tmp.length;++i) CT.ct_TMM_2022[i] ^= tmp[i];
    }

    public void Decrypt(PlainText PT, PublicParam SP, DecryptKey dk, base.LSSS.MCL.Matrix MSP, CipherText CT) {
        ABE.FAME.MCL_swap.PlainText pt_FAME = new ABE.FAME.MCL_swap.PlainText();
        FAME.Decrypt(pt_FAME, MSP, CT.ct_FAME, dk.sk_FAME);
        Mcl.pairing(PT.m, dk.sk_0_4, CT.ct_0_4);
        Mcl.mul(PT.m, pt_FAME.m, PT.m);
        if(SP.type == TYPE.TMM_2022) {
            Mcl.inv(PT.m, PT.m);
            byte[] tmp = PT.m.serialize();
            for(int i = 0;i < tmp.length;++i) tmp[i] ^= CT.ct_TMM_2022[i];
            try {
                PT.m.deserialize(tmp);
            } catch (RuntimeException e) {
                Mcl.inv(GT_tmp[0], PT.m);
                Mcl.mul(PT.m, PT.m, GT_tmp[0]);
            }
        }
    }

    public void DecryptFr(PlainTextFr PT, DecryptKey dk, base.LSSS.MCL.Matrix MSP, CipherText CT) {
        ABE.FAME.MCL_swap.PlainText pt_FAME = new ABE.FAME.MCL_swap.PlainText();
        FAME.Decrypt(pt_FAME, MSP, CT.ct_FAME, dk.sk_FAME);
        Mcl.pairing(GT_tmp[0], dk.sk_0_4, CT.ct_0_4);
        Mcl.mul(GT_tmp[0], pt_FAME.m, GT_tmp[0]);
        Mcl.inv(GT_tmp[0], GT_tmp[0]);
        byte[] tmp = GT_tmp[0].serialize();
        for(int i = 0;i < tmp.length;++i) tmp[i] ^= CT.ct_TMM_2022[i];
        try {
            PT.m.deserialize(tmp);
        } catch (RuntimeException e) {
            PT.m.setInt(0);
        }
    }

    public void Revoke(base.BinaryTree.MCL_G2.RevokeList rl, G2 id, int t) {
        rl.Add(id, t);
    }
}
