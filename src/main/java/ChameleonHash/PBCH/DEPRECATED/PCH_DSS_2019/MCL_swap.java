package ChameleonHash.PBCH.DEPRECATED.PCH_DSS_2019;

import ChameleonHash.CH.DEPRECATED.CH_ET_BC_CDK_2017.Native;
import Encryption.AES_RAW;
import utils.BooleanFormulaParser;
import utils.Hash;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/*
 * Fine-Grained and Controlled Rewriting in Blockchains Chameleon-Hashing Gone Attribute-Based
 * P26. 4.4 A Concrete MCL_swapH
 */

public class MCL_swap {
    public static class PublicParam {
        ABE.FAME.MCL_swap.PublicParam pp_ABE = new ABE.FAME.MCL_swap.PublicParam();
    }

    public static class MasterPublicKey {
        Native.PublicKey pk_CHET = new Native.PublicKey();
        ABE.FAME.MCL_swap.MasterPublicKey mpk_ABE = new ABE.FAME.MCL_swap.MasterPublicKey();
    }

    public static class MasterSecretKey {
        Native.SecretKey sk_CHET = new Native.SecretKey();
        ABE.FAME.MCL_swap.MasterSecretKey msk_ABE = new ABE.FAME.MCL_swap.MasterSecretKey();
    }

    public static class SecretKey {
        Native.SecretKey sk_CHET = new Native.SecretKey();
        ABE.FAME.MCL_swap.SecretKey sk_ABE = new ABE.FAME.MCL_swap.SecretKey();
    }

    public static class HashValue {
        Native.HashValue h_CHET = new Native.HashValue();
        ABE.FAME.MCL_swap.CipherText ct_ABE = new ABE.FAME.MCL_swap.CipherText();
        AES_RAW.CipherText ct_SE = new AES_RAW.CipherText();
    }

    public static class Randomness {
        Native.Randomness r_CHET = new Native.Randomness();
    }

    Native CHET;
    ABE.FAME.MCL_swap ABE;
    Random rand = new Random();

    public MCL_swap(int k) {
        CHET = new Native(k);
        ABE = new ABE.FAME.MCL_swap();
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
        Native.ETrapdoor etd = new Native.ETrapdoor();
        CHET.Hash(H.h_CHET, R.r_CHET, etd, pk_PCH.pk_CHET, m);
        byte[] r = new byte[16];
        rand.nextBytes(r);
        byte[] k = new byte[16];
        rand.nextBytes(k);

        Hash.H_2_Zr u = new Hash.H_2_Zr();
        Hash.H_2_Zr_String_2(u, Arrays.toString(r), MSP.formula);

        Hash.EncText_MCL_GT enc = new Hash.EncText_MCL_GT();
        Hash.Encode_MCL_GT(enc, new Hash.PlaText(k, r));

        ABE.Encrypt(H.ct_ABE, pp_PCH.pp_ABE, pk_PCH.mpk_ABE, MSP, new ABE.FAME.MCL_swap.PlainText(enc.K), u.u_1, u.u_2);

        AES_RAW.Encrypt(H.ct_SE, new AES_RAW.PlainText(etd.sk_ch_2.d.toByteArray()), k);
    }

    public boolean Check(HashValue H, Randomness R, MasterPublicKey pk_PCH, String m) {
        return CHET.Check(H.h_CHET, R.r_CHET, pk_PCH.pk_CHET, m);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam pp_PCH, MasterPublicKey pk_PCH, base.LSSS.MCL.Matrix MSP, SecretKey sk, String m, String m_p) {
        ABE.FAME.MCL_swap.PlainText pt_ABE = new ABE.FAME.MCL_swap.PlainText();
        ABE.Decrypt(pt_ABE, MSP, H.ct_ABE, sk.sk_ABE);

        Hash.PlaText pla = new Hash.PlaText();
        Hash.Decode_MCL_GT(pla, new Hash.EncText_MCL_GT(pt_ABE.m));

        Hash.H_2_Zr u = new Hash.H_2_Zr();
        Hash.H_2_Zr_String_2(u, Arrays.toString(pla.r), MSP.formula);

        ABE.FAME.MCL_swap.CipherText ct_p = new ABE.FAME.MCL_swap.CipherText();
        ABE.Encrypt(ct_p, pp_PCH.pp_ABE, pk_PCH.mpk_ABE, MSP,pt_ABE, u.u_1, u.u_2);

        if(!ct_p.isEqual(H.ct_ABE)) throw new RuntimeException("wrong abe ciphertext");
        Native.ETrapdoor etd = new Native.ETrapdoor();
        AES_RAW.PlainText se_pt = new AES_RAW.PlainText();
        AES_RAW.Decrypt(se_pt, H.ct_SE, pla.k);
        etd.sk_ch_2.d = new BigInteger(se_pt.pt);

        CHET.Adapt(R_p.r_CHET, H.h_CHET, R.r_CHET, etd, pk_PCH.pk_CHET, sk.sk_CHET, m, m_p);
    }
}
