package scheme.PBCH.RPCH_TMM_2022;

import base.GroupParam.MCL.SingleGroup;
import com.herumi.mcl.Fr;
import com.herumi.mcl.GT;
import com.herumi.mcl.G2;
import com.herumi.mcl.Mcl;
import utils.BooleanFormulaParser;
import utils.Func;

/*
 * Revocable Policy-Based ChameleonHash for Blockchain Rewriting
 * P9. 4.2. The proposed RPCH scheme
 */

public class MCL_GT_swap {
    public static class PublicParam {
        public ABE.RABE.MCL_swap.PublicParam SP_RABE = new ABE.RABE.MCL_swap.PublicParam(ABE.RABE.MCL_swap.TYPE.TMM_2022);
        public SingleGroup.SingleGroupGT GP_CHET = new SingleGroup.SingleGroupGT();

        public void H(G2 res, String m) {
            SP_RABE.H(res, m);
        }
    }

    public static class MasterPublicKey {
        public ABE.RABE.MCL_swap.MasterPublicKey mpk_RABE = new ABE.RABE.MCL_swap.MasterPublicKey();
        public GT g = new GT();
    }

    public static class MasterSecretKey {
        public ABE.RABE.MCL_swap.MasterSecretKey msk_RABE = new ABE.RABE.MCL_swap.MasterSecretKey();
    }

    public static class PublicKey {
        GT pk = new GT();
    }

    public static class SecretKey {
        Fr x = new Fr();
        public ABE.RABE.MCL_swap.SecretKey sk_RABE = new ABE.RABE.MCL_swap.SecretKey();
    }

    public static class UpdateKey {
        public ABE.RABE.MCL_swap.UpdateKey ku_RABE = new ABE.RABE.MCL_swap.UpdateKey();
    }

    public static class DecryptKey {
        Fr x = new Fr();
        public ABE.RABE.MCL_swap.DecryptKey dk_RABE = new ABE.RABE.MCL_swap.DecryptKey();
    }

    public static class HashValue {
        GT b = new GT(), h = new GT();
        ABE.RABE.MCL_swap.CipherText ct_RABE = new ABE.RABE.MCL_swap.CipherText();
    }

    public static class Randomness {
        Fr r = new Fr();
    }

    ABE.RABE.MCL_swap RABE = new ABE.RABE.MCL_swap();

    private final GT[] GT_tmp = new GT[]{new GT(), new GT()};
    private final Fr[] Fr_tmp = new Fr[]{new Fr()};

    public void SetUp(MasterPublicKey mpk, MasterSecretKey msk, PublicParam SP) {
        SP.GP_CHET.GetGElement(mpk.g);
        RABE.SetUp(mpk.mpk_RABE, msk.msk_RABE);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, base.BinaryTree.MCL_G2 st, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, BooleanFormulaParser.AttributeList S, G2 id) {
        RABE.KeyGen(sk.sk_RABE, st, SP.SP_RABE, mpk.mpk_RABE, msk.msk_RABE, S, id);
        SP.GP_CHET.GetZrElement(sk.x);
        Mcl.pow(pk.pk, mpk.g, sk.x);
    }

    public void UpdateKeyGen(UpdateKey ku, PublicParam SP, MasterPublicKey mpk, base.BinaryTree.MCL_G2 st, base.BinaryTree.MCL_G2.RevokeList rl, int t) {
        RABE.UpdateKeyGen(ku.ku_RABE, SP.SP_RABE, mpk.mpk_RABE, st, rl, t);
    }

    public void DecryptKeyGen(DecryptKey dk, PublicParam SP, MasterPublicKey mpk, SecretKey sk, UpdateKey ku, base.BinaryTree.MCL_G2 st, base.BinaryTree.MCL_G2.RevokeList rl) {
        RABE.DecryptKeyGen(dk.dk_RABE, SP.SP_RABE, mpk.mpk_RABE, sk.sk_RABE, ku.ku_RABE, st, rl);
        Mcl.neg(dk.x, sk.x);
        Mcl.neg(dk.x, dk.x);
    }

    public void Revoke(base.BinaryTree.MCL_G2.RevokeList rl, G2 id, int t) {
        RABE.Revoke(rl, id, t);
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, MasterPublicKey mpk, PublicKey pk, base.LSSS.MCL.Matrix MSP, Fr m, int t) {
        SP.GP_CHET.GetZrElement(Fr_tmp[0]);
        Func.GetMCLZrRandomElement(R.r);
        Mcl.pow(H.h, mpk.g, Fr_tmp[0]);
        Mcl.pow(H.b, pk.pk, m);
        Mcl.pow(GT_tmp[0], H.h, R.r);
        Mcl.mul(H.b, H.b, GT_tmp[0]);
        RABE.EncryptFr(H.ct_RABE, SP.SP_RABE, mpk.mpk_RABE, MSP, new ABE.RABE.MCL.PlainTextFr(Fr_tmp[0]), t);
    }

    public boolean Check(HashValue H, Randomness R, PublicKey pk, Fr m) {
        Mcl.pow(GT_tmp[0], pk.pk, m);
        Mcl.pow(GT_tmp[1], H.h, R.r);
        Mcl.mul(GT_tmp[0], GT_tmp[0], GT_tmp[1]);
        return H.b.equals(GT_tmp[0]);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicKey pk, DecryptKey dk, base.LSSS.MCL.Matrix MSP, Fr m, Fr m_p) {
        if(!Check(H, R, pk, m)) throw new RuntimeException("wrong hash");
        ABE.RABE.MCL_swap.PlainTextFr pt_RABE = new ABE.RABE.MCL_swap.PlainTextFr();
        RABE.DecryptFr(pt_RABE, dk.dk_RABE, MSP, H.ct_RABE);
        Mcl.div(pt_RABE.m, dk.x, pt_RABE.m);
        Mcl.sub(Fr_tmp[0], m, m_p);
        Mcl.mul(pt_RABE.m, Fr_tmp[0], pt_RABE.m);
        Mcl.add(R_p.r, R.r, pt_RABE.m);
    }
}
