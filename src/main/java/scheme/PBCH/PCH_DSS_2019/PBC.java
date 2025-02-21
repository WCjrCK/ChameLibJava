package scheme.PBCH.PCH_DSS_2019;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import utils.BooleanFormulaParser;
import utils.Hash;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/*
 * Fine-Grained and Controlled Rewriting in Blockchains Chameleon-Hashing Gone Attribute-Based
 * P26. 4.4 A Concrete PBCH
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey pk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey();
        public ABE.FAME.PBC.PublicParam mpk_ABE = new ABE.FAME.PBC.PublicParam();
    }

    public static class MasterSecretKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
        ABE.FAME.PBC.MasterSecretKey msk_ABE = new ABE.FAME.PBC.MasterSecretKey();
    }

    public static class SecretKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
        ABE.FAME.PBC.SecretKey sk_ABE = new ABE.FAME.PBC.SecretKey();
    }

    public static class HashValue {
        scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue h_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue();
        ABE.FAME.PBC.CipherText ct_ABE = new ABE.FAME.PBC.CipherText();
        SE.AES.CipherText ct_SE = new SE.AES.CipherText();
    }

    public static class Randomness {
        scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness r_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
    }

    private static class H4U {
        public Element u_1, u_2;
    }

    private void H4(H4U u, Field G, String m1, String m2) {
        u.u_1 = Hash.H_String_1_PBC_1(G, m1 + "|" + m2);
        u.u_2 = Hash.H_String_1_PBC_1(G, m2 + "|" + m1);
    }

    private static class EncText {
        public Element K;
    }

    private static class PlaText {
        public byte[] k;
        public byte[] r;
    }

    private void Encode(EncText K, Field G, PlaText P) {
        byte[] tmp = new byte[G.getLengthInBytes()];
        tmp[1] = (byte) P.k.length;
        System.arraycopy(P.k, 0, tmp, 2, P.k.length);
        tmp[G.getLengthInBytes() / 2 + 1] = (byte) P.r.length;
        System.arraycopy(P.r, 0, tmp, G.getLengthInBytes() / 2 + 2, P.r.length);
        K.K = G.newElementFromBytes(tmp).getImmutable();
    }

    private void Decode(PlaText P, EncText K) {
        byte[] tmp = K.K.toBytes();
        int l1 = tmp[1];
        if(l1 >= tmp.length) throw new RuntimeException("Decode Failed");
        P.k = new byte[l1];
        System.arraycopy(tmp, 2, P.k, 0, l1);
        int l2 = tmp[K.K.getLengthInBytes() / 2 + 1];
        if(l2 + K.K.getLengthInBytes() / 2 >= tmp.length) throw new RuntimeException("Decode Failed");
        P.r = new byte[l2];
        System.arraycopy(tmp, K.K.getLengthInBytes() / 2 + 2, P.r, 0, l2);
    }

    scheme.CH.CH_ET_BC_CDK_2017.Native CHET;
    ABE.FAME.PBC ABE;
    Random rand = new Random();

    public PBC(int k) {
        CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native(k);
        ABE = new ABE.FAME.PBC();
    }

    public void SetUp(PublicParam pk_PCH, MasterSecretKey sk_PCH, curve.PBC curve, boolean swap_G1G2) {
        CHET.KeyGen(pk_PCH.pk_CHET, sk_PCH.sk_CHET);
        ABE.SetUp(pk_PCH.mpk_ABE, sk_PCH.msk_ABE, curve, swap_G1G2);
    }

    public void KeyGen(SecretKey sk, PublicParam pk_PCH, MasterSecretKey sk_PCH, BooleanFormulaParser.AttributeList S) {
        sk.sk_CHET = sk_PCH.sk_CHET;
        ABE.KeyGen(sk.sk_ABE, sk_PCH.msk_ABE, pk_PCH.mpk_ABE, S);
    }

    public void Hash(HashValue H, Randomness R, PublicParam pk_PCH, base.LSSS.PBC.Matrix MSP, BigInteger m) {
        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        CHET.Hash(H.h_CHET, R.r_CHET, etd, pk_PCH.pk_CHET, m);
        byte[] r = new byte[CHET.CH.lambda / 8];
        rand.nextBytes(r);
        byte[] k = new byte[CHET.CH.lambda / 8];
        rand.nextBytes(k);

        H4U u = new H4U();
        H4(u, pk_PCH.mpk_ABE.Zr, Arrays.toString(r), MSP.formula);

        PlaText pla = new PlaText();
        pla.r = r;
        pla.k = k;
        EncText enc = new EncText();
        Encode(enc, pk_PCH.mpk_ABE.GT, pla);

        ABE.FAME.PBC.PlainText pt_ABE = new ABE.FAME.PBC.PlainText(enc.K);
        ABE.Encrypt(H.ct_ABE, pk_PCH.mpk_ABE, MSP, pt_ABE, u.u_1, u.u_2);

        SE.AES.PlainText se_pt = new SE.AES.PlainText();
        se_pt.pt = etd.sk_ch_2.d.toByteArray();
        SE.AES.Encrypt(H.ct_SE, se_pt, k);
    }

    public boolean Check(HashValue H, Randomness R, PublicParam pk_PCH, BigInteger m) {
        return CHET.Check(H.h_CHET, R.r_CHET, pk_PCH.pk_CHET, m);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam pk_PCH, base.LSSS.PBC.Matrix MSP, SecretKey sk, BigInteger m, BigInteger m_p) {
        ABE.FAME.PBC.PlainText pt_ABE = new ABE.FAME.PBC.PlainText();
        ABE.Decrypt(pt_ABE, pk_PCH.mpk_ABE, MSP, H.ct_ABE, sk.sk_ABE);

        PlaText pla = new PlaText();
        EncText enc = new EncText();
        enc.K = pt_ABE.m;
        Decode(pla, enc);

        H4U u = new H4U();
        H4(u, pk_PCH.mpk_ABE.Zr, Arrays.toString(pla.r), MSP.formula);

        ABE.FAME.PBC.CipherText ct_p = new ABE.FAME.PBC.CipherText();
        ABE.Encrypt(ct_p, pk_PCH.mpk_ABE, MSP,pt_ABE, u.u_1, u.u_2);

        if(!ct_p.isEqual(H.ct_ABE)) throw new RuntimeException("wrong abe ciphertext");
        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        SE.AES.PlainText se_pt = new SE.AES.PlainText();
        SE.AES.Decrypt(se_pt, H.ct_SE, pla.k);
        etd.sk_ch_2.d = new BigInteger(se_pt.pt);

        CHET.Adapt(R_p.r_CHET, H.h_CHET, R.r_CHET, etd, pk_PCH.pk_CHET, sk.sk_CHET, m, m_p);
    }
}
