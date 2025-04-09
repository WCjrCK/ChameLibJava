package scheme.PBCH.RPCH_XNM_2021;

import com.herumi.mcl.G1;
import utils.BooleanFormulaParser;
import utils.Hash;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/*
 * Revocable Policy-Based Chameleon Hash
 * P13. 5.2 Proposed RPCH
 */

public class MCL {
    public static class PublicParam {
        public ABE.RABE.MCL.PublicParam SP_RABE = new ABE.RABE.MCL.PublicParam(ABE.RABE.MCL.TYPE.XNM_2021);

        public void H(G1 res, String m) {
            SP_RABE.H(res, m);
        }
    }

    public static class MasterPublicKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey pk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey();
        public ABE.RABE.MCL.MasterPublicKey mpk_RABE = new ABE.RABE.MCL.MasterPublicKey();
    }

    public static class MasterSecretKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
        public ABE.RABE.MCL.MasterSecretKey msk_RABE = new ABE.RABE.MCL.MasterSecretKey();
    }

    public static class SecretKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
        public ABE.RABE.MCL.SecretKey sk_RABE = new ABE.RABE.MCL.SecretKey();
    }

    public static class UpdateKey {
        public ABE.RABE.MCL.UpdateKey ku_RABE = new ABE.RABE.MCL.UpdateKey();
    }

    public static class DecryptKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
        public ABE.RABE.MCL.DecryptKey dk_RABE = new ABE.RABE.MCL.DecryptKey();
    }

    public static class HashValue {
        scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue h_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue();
        ABE.RABE.MCL.CipherText ct_RABE = new ABE.RABE.MCL.CipherText();
        SE.AES.CipherText ct_SE = new SE.AES.CipherText();
    }

    public static class Randomness {
        scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness r_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
    }

    ABE.RABE.MCL RABE;
    scheme.CH.CH_ET_BC_CDK_2017.Native CHET;
    Random rand = new Random();

    public MCL(int k) {
        CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native(k);
        RABE = new ABE.RABE.MCL();
    }

    public void SetUp(MasterPublicKey mpk, MasterSecretKey msk) {
        CHET.KeyGen(mpk.pk_CHET, msk.sk_CHET);
        RABE.SetUp(mpk.mpk_RABE, msk.msk_RABE);
    }

    public void KeyGen(SecretKey sk, base.BinaryTree.MCL_G1 st, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, BooleanFormulaParser.AttributeList S, G1 id) {
        RABE.KeyGen(sk.sk_RABE, st, SP.SP_RABE, mpk.mpk_RABE, msk.msk_RABE, S, id);
        sk.sk_CHET.CopyFrom(msk.sk_CHET);
    }

    public void UpdateKeyGen(UpdateKey ku, PublicParam SP, MasterPublicKey mpk, base.BinaryTree.MCL_G1 st, base.BinaryTree.MCL_G1.RevokeList rl, int t) {
        RABE.UpdateKeyGen(ku.ku_RABE, SP.SP_RABE, mpk.mpk_RABE, st, rl, t);
    }

    public void DecryptKeyGen(DecryptKey dk, PublicParam SP, MasterPublicKey mpk, SecretKey sk, UpdateKey ku, base.BinaryTree.MCL_G1 st, base.BinaryTree.MCL_G1.RevokeList rl) {
        RABE.DecryptKeyGen(dk.dk_RABE, SP.SP_RABE, mpk.mpk_RABE, sk.sk_RABE, ku.ku_RABE, st, rl);
        dk.sk_CHET.CopyFrom(sk.sk_CHET);
    }

    public void Revoke(base.BinaryTree.MCL_G1.RevokeList rl, G1 id, int t) {
        RABE.Revoke(rl, id, t);
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, MasterPublicKey mpk, base.LSSS.MCL.Matrix MSP, String m, int t) {
        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        CHET.Hash(H.h_CHET, R.r_CHET, etd, mpk.pk_CHET, m);
        byte[] r = new byte[16];
        rand.nextBytes(r);
        byte[] k = new byte[16];
        rand.nextBytes(k);
        Hash.EncText_MCL_GT enc = new Hash.EncText_MCL_GT();
        Hash.Encode_MCL_GT(enc, new Hash.PlaText(k, r));

        Hash.H_2_Zr u = new Hash.H_2_Zr();
        Hash.H_2_Zr_String_3(u, Arrays.toString(r), MSP.formula, String.valueOf(t));
        RABE.Encrypt(H.ct_RABE, SP.SP_RABE, mpk.mpk_RABE, MSP, new ABE.RABE.MCL.PlainText(enc.K), t, u.u_1, u.u_2);

        SE.AES.Encrypt(H.ct_SE, new SE.AES.PlainText(etd.sk_ch_2.d.toByteArray()), k);
    }

    public boolean Check(HashValue H, Randomness R, MasterPublicKey mpk, String m) {
        return CHET.Check(H.h_CHET, R.r_CHET, mpk.pk_CHET, m);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam SP, MasterPublicKey mpk, DecryptKey dk, base.LSSS.MCL.Matrix MSP, String m, String m_p) {
        if(!Check(H, R, mpk, m)) throw new RuntimeException("wrong hash");
        ABE.RABE.MCL.PlainText pt_RABE = new ABE.RABE.MCL.PlainText();
        RABE.Decrypt(pt_RABE, SP.SP_RABE, dk.dk_RABE, MSP, H.ct_RABE);

        Hash.PlaText pla = new Hash.PlaText();
        Hash.Decode_MCL_GT(pla, new Hash.EncText_MCL_GT(pt_RABE.m));

        Hash.H_2_Zr u = new Hash.H_2_Zr();
        Hash.H_2_Zr_String_3(u, Arrays.toString(pla.r), MSP.formula, String.valueOf(dk.dk_RABE.t));

        ABE.RABE.MCL.CipherText ct_RABE = new ABE.RABE.MCL.CipherText();
        RABE.Encrypt(ct_RABE, SP.SP_RABE, mpk.mpk_RABE, MSP, pt_RABE, dk.dk_RABE.t, u.u_1, u.u_2);

        if(!ct_RABE.isEqual(H.ct_RABE)) throw new RuntimeException("wrong rabe ciphertext");

        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        SE.AES.PlainText se_pt = new SE.AES.PlainText();
        SE.AES.Decrypt(se_pt, H.ct_SE, pla.k);
        etd.sk_ch_2.d = new BigInteger(se_pt.pt);

        CHET.Adapt(R_p.r_CHET, H.h_CHET, R.r_CHET, etd, mpk.pk_CHET, dk.sk_CHET, m, m_p);
    }
}
