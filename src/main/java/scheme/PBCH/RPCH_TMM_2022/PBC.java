package scheme.PBCH.RPCH_TMM_2022;

import base.GroupParam.PBC.Asymmetry;
import base.GroupParam.PBC.SingleGroup;
import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import utils.BooleanFormulaParser;

/*
 * Revocable Policy-Based ChameleonHash for Blockchain Rewriting
 * P9. 4.2. The proposed RPCH scheme
 */

public class PBC {
    public static class PublicParam {
        public ABE.RABE.PBC.PublicParam SP_RABE;
        public Asymmetry GP;
        public SingleGroup GP_CHET;

        public PublicParam(curve.PBC curve, boolean swap_G1G2, Group group) {
            GP = new Asymmetry(curve, swap_G1G2);
            GP_CHET = new SingleGroup(curve, group);
            SP_RABE = new ABE.RABE.PBC.PublicParam(ABE.RABE.PBC.TYPE.TMM_2022, GP);
        }

        public PublicParam(Asymmetry GP, SingleGroup GP_CHET) {
            this.GP = GP;
            this.GP_CHET = GP_CHET;
            SP_RABE = new ABE.RABE.PBC.PublicParam(ABE.RABE.PBC.TYPE.TMM_2022, GP);
        }

        public Element H(String m) {
            return SP_RABE.H(m);
        }
    }

    public static class MasterPublicKey {
        public ABE.RABE.PBC.MasterPublicKey mpk_RABE = new ABE.RABE.PBC.MasterPublicKey();
        public Element g;
    }

    public static class MasterSecretKey {
        public ABE.RABE.PBC.MasterSecretKey msk_RABE = new ABE.RABE.PBC.MasterSecretKey();
    }

    public static class PublicKey {
        Element pk;
    }

    public static class SecretKey {
        Element x;
        public ABE.RABE.PBC.SecretKey sk_RABE = new ABE.RABE.PBC.SecretKey();
    }

    public static class UpdateKey {
        public ABE.RABE.PBC.UpdateKey ku_RABE = new ABE.RABE.PBC.UpdateKey();
    }

    public static class DecryptKey {
        Element x;
        public ABE.RABE.PBC.DecryptKey dk_RABE = new ABE.RABE.PBC.DecryptKey();
    }

    public static class HashValue {
        Element b, h;
        ABE.RABE.PBC.CipherText ct_RABE = new ABE.RABE.PBC.CipherText();
    }

    public static class Randomness {
        Element r;
    }

    ABE.RABE.PBC RABE = new ABE.RABE.PBC();

    public void SetUp(MasterPublicKey mpk, MasterSecretKey msk, PublicParam SP) {
        mpk.g = SP.GP_CHET.GetGElement();
        RABE.SetUp(mpk.mpk_RABE, msk.msk_RABE, SP.SP_RABE);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, base.BinaryTree.PBC st, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, BooleanFormulaParser.AttributeList S, Element id) {
        RABE.KeyGen(sk.sk_RABE, st, SP.SP_RABE, mpk.mpk_RABE, msk.msk_RABE, S, id);
        sk.x = SP.GP_CHET.GetZrElement();
        pk.pk = mpk.g.powZn(sk.x).getImmutable();
    }

    public void UpdateKeyGen(UpdateKey ku, PublicParam SP, MasterPublicKey mpk, base.BinaryTree.PBC st, base.BinaryTree.PBC.RevokeList rl, int t) {
        RABE.UpdateKeyGen(ku.ku_RABE, SP.SP_RABE, mpk.mpk_RABE, st, rl, t);
    }

    public void DecryptKeyGen(DecryptKey dk, PublicParam SP, MasterPublicKey mpk, SecretKey sk, UpdateKey ku, base.BinaryTree.PBC st, base.BinaryTree.PBC.RevokeList rl) {
        RABE.DecryptKeyGen(dk.dk_RABE, SP.SP_RABE, mpk.mpk_RABE, sk.sk_RABE, ku.ku_RABE, st, rl);
        dk.x = sk.x;
    }

    public void Revoke(base.BinaryTree.PBC.RevokeList rl, Element id, int t) {
        RABE.Revoke(rl, id, t);
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, MasterPublicKey mpk, PublicKey pk, base.LSSS.PBC.Matrix MSP, Element m, int t) {
        Element R_ = SP.GP_CHET.GetZrElement();
        R.r = SP.GP.GetZrElement();
        H.h = mpk.g.powZn(R_);
        H.b = pk.pk.powZn(m).mul(H.h.powZn(R.r)).getImmutable();
        RABE.Encrypt(H.ct_RABE, SP.SP_RABE, mpk.mpk_RABE, MSP, new ABE.RABE.PBC.PlainText(R_), t);
    }

    public boolean Check(HashValue H, Randomness R, PublicKey pk, Element m) {
        return H.b.isEqual(pk.pk.powZn(m).mul(H.h.powZn(R.r)));
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam SP, PublicKey pk, DecryptKey dk, base.LSSS.PBC.Matrix MSP, Element m, Element m_p) {
        if(!Check(H, R, pk, m)) throw new RuntimeException("wrong hash");
        ABE.RABE.PBC.PlainText pt_RABE = new ABE.RABE.PBC.PlainText();
        RABE.Decrypt(pt_RABE, SP.SP_RABE, dk.dk_RABE, MSP, H.ct_RABE);
        Element R_ = pt_RABE.m;
        R_p.r = R.r.add(m.sub(m_p).mul(dk.x.div(R_)));
    }
}
