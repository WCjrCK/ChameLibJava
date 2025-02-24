package ABE.RABE;

import it.unisa.dia.gas.jpbc.Element;
import utils.BooleanFormulaParser;

import java.util.HashMap;

/*
 * Revocable Policy-Based Chameleon Hash
 * P12. 5.1 Proposed RABE
 */

public class PBC {
    public static class PublicParam {
        public ABE.FAME.PBC.PublicParam pp_FAME;
        public base.GroupParam.PBC GP;

        public PublicParam(curve.PBC curve, boolean swap_G1G2) {
            GP = new base.GroupParam.PBC(curve, swap_G1G2);
            pp_FAME = new ABE.FAME.PBC.PublicParam(GP);
        }

        public PublicParam(base.GroupParam.PBC GP) {
            this.GP = GP;
            pp_FAME = new ABE.FAME.PBC.PublicParam(GP);
        }

        public Element H(String m) {
            return pp_FAME.H(m);
        }
    }

    public static class MasterPublicKey {
        public ABE.FAME.PBC.MasterPublicKey mpk_FAME = new ABE.FAME.PBC.MasterPublicKey();
    }

    public static class MasterSecretKey {
        public ABE.FAME.PBC.MasterSecretKey msk_FAME = new ABE.FAME.PBC.MasterSecretKey();
    }

    public static class SecretKey {
        public ABE.FAME.PBC.SecretKey sk_FAME = new ABE.FAME.PBC.SecretKey();
        public HashMap<Integer, Element> sk_theta = new HashMap<>();
        int node_id;
    }

    public static class UpdateKey {
        int t;
        public HashMap<Integer, Element[]> ku_theta = new HashMap<>();

        public void AddKey(int theta, Element k_u_theta_0, Element k_u_theta_1) {
            Element[] res = new Element[2];
            res[0] = k_u_theta_0;
            res[1] = k_u_theta_1;
            ku_theta.put(theta, res);
        }
    }

    public static class DecryptKey {
        public int node_id, t;
        public ABE.FAME.PBC.SecretKey sk_FAME = new ABE.FAME.PBC.SecretKey();
        public Element sk_0_4;

        public void CopyFrom(SecretKey sk) {
            sk_FAME.CopyFrom(sk.sk_FAME);
        }
    }

    public static class CipherText {
        public ABE.FAME.PBC.CipherText ct_FAME = new ABE.FAME.PBC.CipherText();
        Element ct_0_4;

        public boolean isEqual(CipherText CT_p) {
            return ct_FAME.isEqual(CT_p.ct_FAME) && ct_0_4.isEqual(CT_p.ct_0_4);
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

    public ABE.FAME.PBC FAME = new ABE.FAME.PBC();

    public void SetUp(MasterPublicKey mpk, MasterSecretKey msk, PublicParam SP) {
        FAME.SetUp(SP.pp_FAME, mpk.mpk_FAME, msk.msk_FAME);
    }

    public void KeyGen(SecretKey sk, base.BinaryTree.PBC st, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, BooleanFormulaParser.AttributeList S, Element id) {
        FAME.KeyGen(sk.sk_FAME, SP.pp_FAME, mpk.mpk_FAME, msk.msk_FAME, S);

        int theta = st.Pick(id);
        sk.node_id = theta;
        if(!st.tag_g.get(theta)) st.Setg(theta, SP.GP.GetG1Element());
        sk.sk_theta.put(theta, sk.sk_FAME.sk_p[2].div(st.g_theta[theta]));
        while(theta != 0) {
            theta = st.GetFNodeId(theta);
            if(!st.tag_g.get(theta)) st.Setg(theta, SP.GP.GetG1Element());
            sk.sk_theta.put(theta, sk.sk_FAME.sk_p[2].div(st.g_theta[theta]));
        }
        // hide g^d3g^{-rho_p}/g_theta
        sk.sk_FAME.sk_p[2] = SP.GP.GetG1Element();
    }

    public void UpdateKeyGen(UpdateKey ku, PublicParam SP, MasterPublicKey mpk, base.BinaryTree.PBC st, base.BinaryTree.PBC.RevokeList rl, int t) {
        st.GetUpdateKeyNode(rl, t);
        ku.t = t;
        Element r_theta;
        for(int theta = 0;theta < st.g_theta.length;++theta) {
            if(st.tag.get(theta) && st.tag_g.get(theta)) {
                r_theta = SP.GP.GetZrElement();
                ku.AddKey(theta,
                        st.g_theta[theta].mul(SP.H("1" + t).powZn(r_theta)).getImmutable(),
                        mpk.mpk_FAME.h.powZn(r_theta).getImmutable()
                );
            }
        }
    }

    public void DecryptKeyGen(DecryptKey dk, PublicParam SP, MasterPublicKey mpk, SecretKey sk, UpdateKey ku, base.BinaryTree.PBC st, base.BinaryTree.PBC.RevokeList rl) {
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
            Element r_theta_p = SP.GP.GetZrElement();
            Element[] ku_theta = ku.ku_theta.get(theta);
            dk.sk_FAME.sk_p[2] = sk.sk_theta.get(theta).mul(ku_theta[0]).mul(SP.H("1" + dk.t).powZn(r_theta_p)).getImmutable();
            dk.sk_0_4 = ku_theta[1].mul(mpk.mpk_FAME.h.powZn(r_theta_p)).getImmutable();
        }
    }

    public void Encrypt(CipherText CT, PublicParam SP, MasterPublicKey mpk, base.LSSS.PBC.Matrix MSP, PlainText PT, int t) {
        Element s_1 = SP.GP.GetZrElement();
        Element s_2 = SP.GP.GetZrElement();
        Encrypt(CT, SP, mpk, MSP, PT, t, s_1, s_2);
    }

    public void Encrypt(CipherText CT, PublicParam SP, MasterPublicKey mpk, base.LSSS.PBC.Matrix MSP, PlainText PT, int t, Element s_1, Element s_2) {
        FAME.Encrypt(CT.ct_FAME, SP.pp_FAME, mpk.mpk_FAME, MSP, new ABE.FAME.PBC.PlainText(PT.m), s_1, s_2);
        CT.ct_0_4 = SP.H("1" + t).powZn(s_1.add(s_2)).getImmutable();
    }

    public void Decrypt(PlainText PT, PublicParam SP, DecryptKey dk, base.LSSS.PBC.Matrix MSP, CipherText CT) {
        ABE.FAME.PBC.PlainText pt_FAME = new ABE.FAME.PBC.PlainText();
        FAME.Decrypt(pt_FAME, SP.pp_FAME, MSP, CT.ct_FAME, dk.sk_FAME);
        PT.m = pt_FAME.m.mul(SP.GP.pairing(CT.ct_0_4, dk.sk_0_4)).getImmutable();
    }

    public void Revoke(base.BinaryTree.PBC.RevokeList rl, Element id, int t) {
        rl.Add(id, t);
    }
}
