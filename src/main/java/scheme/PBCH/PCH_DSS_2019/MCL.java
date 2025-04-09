package scheme.PBCH.PCH_DSS_2019;

import utils.BooleanFormulaParser;
import utils.Hash;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/*
 * Fine-Grained and Controlled Rewriting in Blockchains Chameleon-Hashing Gone Attribute-Based
 * P26. 4.4 A Concrete MCLH
 */

public class MCL {
    public static class PublicParam {
        ABE.FAME.MCL.PublicParam pp_ABE = new ABE.FAME.MCL.PublicParam();
    }

    public static class MasterPublicKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey pk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey();
        ABE.FAME.MCL.MasterPublicKey mpk_ABE = new ABE.FAME.MCL.MasterPublicKey();
    }

    public static class MasterSecretKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
        ABE.FAME.MCL.MasterSecretKey msk_ABE = new ABE.FAME.MCL.MasterSecretKey();
    }

    public static class SecretKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
        ABE.FAME.MCL.SecretKey sk_ABE = new ABE.FAME.MCL.SecretKey();
    }

    public static class HashValue {
        scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue h_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue();
        ABE.FAME.MCL.CipherText ct_ABE = new ABE.FAME.MCL.CipherText();
        SE.AES.CipherText ct_SE = new SE.AES.CipherText();
    }

    public static class Randomness {
        scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness r_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
    }

    scheme.CH.CH_ET_BC_CDK_2017.Native CHET;
    ABE.FAME.MCL ABE;
    Random rand = new Random();

    public MCL(int k) {
        CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native(k);
        ABE = new ABE.FAME.MCL();
    }

    public void SetUp(MasterPublicKey pk_PCH, MasterSecretKey sk_PCH) {
        CHET.KeyGen(pk_PCH.pk_CHET, sk_PCH.sk_CHET);
        ABE.SetUp(pk_PCH.mpk_ABE, sk_PCH.msk_ABE);
    }

    public void KeyGen(SecretKey sk, PublicParam pp_PCH, MasterPublicKey pk_PCH, MasterSecretKey sk_PCH, BooleanFormulaParser.AttributeList S) {
        sk.sk_CHET = sk_PCH.sk_CHET;
        ABE.KeyGen(sk.sk_ABE, pp_PCH.pp_ABE, pk_PCH.mpk_ABE, sk_PCH.msk_ABE, S);
    }

    public void Hash(HashValue H, Randomness R, PublicParam pp_PCH, MasterPublicKey pk_PCH, base.LSSS.MCL.Matrix MSP, String m) {
        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        CHET.Hash(H.h_CHET, R.r_CHET, etd, pk_PCH.pk_CHET, m);
        byte[] r = new byte[16];
        rand.nextBytes(r);
        byte[] k = new byte[16];
        rand.nextBytes(k);

        Hash.H_2_Zr u = new Hash.H_2_Zr();
        Hash.H_2_Zr_String_2(u, Arrays.toString(r), MSP.formula);

        Hash.EncText_MCL_GT enc = new Hash.EncText_MCL_GT();
        Hash.Encode_MCL_GT(enc, new Hash.PlaText(k, r));

        ABE.Encrypt(H.ct_ABE, pp_PCH.pp_ABE, pk_PCH.mpk_ABE, MSP, new ABE.FAME.MCL.PlainText(enc.K), u.u_1, u.u_2);

        SE.AES.Encrypt(H.ct_SE, new SE.AES.PlainText(etd.sk_ch_2.d.toByteArray()), k);
    }

    public boolean Check(HashValue H, Randomness R, MasterPublicKey pk_PCH, String m) {
        return CHET.Check(H.h_CHET, R.r_CHET, pk_PCH.pk_CHET, m);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam pp_PCH, MasterPublicKey pk_PCH, base.LSSS.MCL.Matrix MSP, SecretKey sk, String m, String m_p) {
        ABE.FAME.MCL.PlainText pt_ABE = new ABE.FAME.MCL.PlainText();
        ABE.Decrypt(pt_ABE, MSP, H.ct_ABE, sk.sk_ABE);

        Hash.PlaText pla = new Hash.PlaText();
        Hash.Decode_MCL_GT(pla, new Hash.EncText_MCL_GT(pt_ABE.m));

        Hash.H_2_Zr u = new Hash.H_2_Zr();
        Hash.H_2_Zr_String_2(u, Arrays.toString(pla.r), MSP.formula);

        ABE.FAME.MCL.CipherText ct_p = new ABE.FAME.MCL.CipherText();
        ABE.Encrypt(ct_p, pp_PCH.pp_ABE, pk_PCH.mpk_ABE, MSP,pt_ABE, u.u_1, u.u_2);

        if(!ct_p.isEqual(H.ct_ABE)) throw new RuntimeException("wrong abe ciphertext");
        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        SE.AES.PlainText se_pt = new SE.AES.PlainText();
        SE.AES.Decrypt(se_pt, H.ct_SE, pla.k);
        etd.sk_ch_2.d = new BigInteger(se_pt.pt);

        CHET.Adapt(R_p.r_CHET, H.h_CHET, R.r_CHET, etd, pk_PCH.pk_CHET, sk.sk_CHET, m, m_p);
    }
}
