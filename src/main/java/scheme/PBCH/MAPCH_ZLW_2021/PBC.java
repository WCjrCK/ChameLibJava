package scheme.PBCH.MAPCH_ZLW_2021;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.math.BigInteger;

/*
 * Redactable Transactions in Consortium Blockchain Controlled by Multi-authority CP-ABE
 * P11. 3.2 Generic Construction and Security Analysis
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        public base.GroupParam.PBC.Symmetry GP;
        public ABE.MA_ABE.PBC.PublicParam pp_ABE;
        scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey hk = new scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey();
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey tk = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();

        public PublicParam(curve.PBC curve) {
            GP = new base.GroupParam.PBC.Symmetry(curve);
            pp_ABE = new ABE.MA_ABE.PBC.PublicParam(GP);
        }
    }

    public static class Authority {
        private final MasterSecretKey mtk = new MasterSecretKey();
        public PublicKey mhk;
        public ABE.MA_ABE.PBC.Authority MA_ABE_Auth;

        public Authority(String theta, PublicParam SP) {
            mhk = new PublicKey(SP);
            mtk.tk = SP.tk;
            MA_ABE_Auth = new ABE.MA_ABE.PBC.Authority(theta);
        }
    }

    public static class PublicKey {
        ABE.MA_ABE.PBC.PublicParam pp_ABE;
        scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey hk;

        public PublicKey(PublicParam SP) {
            pp_ABE = SP.pp_ABE;
            hk = SP.hk;
        }
    }

    public static class MasterSecretKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey tk = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
    }

    public static class SecretKey {
        ABE.MA_ABE.PBC.SecretKey MA_ABE_SK = new ABE.MA_ABE.PBC.SecretKey();
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey tk = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
    }

    public static class PublicKeyGroup {
        ABE.MA_ABE.PBC.PublicKeyGroup MA_ABE_PKG = new ABE.MA_ABE.PBC.PublicKeyGroup();
        scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey hk;
        ABE.MA_ABE.PBC.PublicParam pp_ABE;

        public PublicKeyGroup(PublicParam SP) {
            pp_ABE = SP.pp_ABE;
            hk = SP.hk;
        }

        public void AddPK(Authority Auth) {
            MA_ABE_PKG.AddPK(Auth.MA_ABE_Auth);
        }
    }

    public static class SecretKeyGroup {
        ABE.MA_ABE.PBC.SecretKeyGroup MA_ABE_SKG = new ABE.MA_ABE.PBC.SecretKeyGroup();
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey tk = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();

        public void AddSK(SecretKey SK) {
            MA_ABE_SKG.AddSK(SK.MA_ABE_SK);
            tk = SK.tk;
        }
    }

    public static class HashValue {
        scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue CHET_H = new scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue();
        ABE.MA_ABE.PBC.CipherText MA_ABE_C = new ABE.MA_ABE.PBC.CipherText();
    }

    public static class Randomness {
        scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness CHET_R = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
    }

    scheme.CH.CH_ET_BC_CDK_2017.Native CHET;
    ABE.MA_ABE.PBC MA_ABE = new ABE.MA_ABE.PBC();

//    private Element BigInteger2G(Field G, BigInteger m) {
//        byte[] tmp = new byte[m.toByteArray().length + 2];
//        tmp[1] = (byte) m.toByteArray().length;
//        System.arraycopy(m.toByteArray(), 0, tmp, 2, m.toByteArray().length);
//        return G.newElementFromBytes(tmp);
//    }
//
//    private BigInteger G2BigInteger(Element t) {
//        byte[] tmp = t.toBytes();
//        int l = tmp[1];
//        if(l <= 0 || l + 2 >= tmp.length) throw new RuntimeException("decode error");
//        return new BigInteger(tmp, 2, l);
//    }

    private Element BigInteger2G(Field G, BigInteger m) {
        byte[] tmp = new byte[m.toByteArray().length];
        System.arraycopy(m.toByteArray(), 0, tmp, 0, m.toByteArray().length);
        byte[] tmp2 = new byte[G.getLengthInBytes()];
        int l1 = m.toByteArray().length / 2;
        int l2 = m.toByteArray().length - l1;
        tmp2[1] = (byte) l1;
        tmp2[G.getLengthInBytes() / 2 + 1] = (byte) l2;
        System.arraycopy(tmp, 0, tmp2, 2, l1);
        System.arraycopy(tmp, l1, tmp2, G.getLengthInBytes() / 2 + 2, l2);
        return G.newElementFromBytes(tmp2);
    }

    private BigInteger G2BigInteger(Element t) {
        byte[] tmp = t.toBytes();
        int l1 = tmp[1];
        int l2 = tmp[t.getLengthInBytes() / 2 + 1];
        int l = l1 + l2;
        if(l <= 0 || l + 4 >= tmp.length) throw new RuntimeException("decode error");
        byte[] tmp2 = new byte[l];
        System.arraycopy(tmp, 2, tmp2, 0, l1);
        System.arraycopy(tmp, t.getLengthInBytes() / 2 + 2, tmp2, l1, l2);
        return new BigInteger(tmp2, 0, l);
    }

    public PBC(int lambda) {
        CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native(lambda);
    }

    public void SetUp(PublicParam SP) {
        CHET.KeyGen(SP.hk, SP.tk);
    }

    public void AuthSetup(Authority Auth) {
        MA_ABE.AuthSetup(Auth.MA_ABE_Auth, Auth.mhk.pp_ABE);
    }

    public void KeyGen(Authority Auth, SecretKey msk_i, String GID, String i) {
        MA_ABE.KeyGen(Auth.MA_ABE_Auth, msk_i.MA_ABE_SK, i, Auth.mhk.pp_ABE, GID);
        msk_i.tk = Auth.mtk.tk;
    }

    public void Hash(HashValue H, Randomness R, PublicKeyGroup MHKS, base.LSSS.PBC.Matrix MSP, String m) {
        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        CHET.Hash(H.CHET_H, R.CHET_R, etd, MHKS.hk, m);
        ABE.MA_ABE.PBC.PlainText MA_ABE_PT = new ABE.MA_ABE.PBC.PlainText(BigInteger2G(MHKS.pp_ABE.GP.GT, etd.sk_ch_2.d).getImmutable());
        MA_ABE.Encrypt(H.MA_ABE_C, MHKS.pp_ABE, MHKS.MA_ABE_PKG, MSP, MA_ABE_PT);
    }

    public boolean Check(HashValue H, Randomness R, PublicKeyGroup MHKS, String m) {
        return CHET.Check(H.CHET_H, R.CHET_R, MHKS.hk, m);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicKeyGroup MHKS, SecretKeyGroup MSKS, base.LSSS.PBC.Matrix MSP, String m, String m_p) {
        if(!Check(H, R, MHKS, m)) throw new RuntimeException("Wrong Hash Value");
        ABE.MA_ABE.PBC.PlainText MA_ABE_PT = new ABE.MA_ABE.PBC.PlainText(MHKS.pp_ABE.GP.GetGTElement());
        MA_ABE.Decrypt(MA_ABE_PT, MHKS.pp_ABE, MSKS.MA_ABE_SKG, MSP, H.MA_ABE_C);
        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        etd.sk_ch_2.d = G2BigInteger(MA_ABE_PT.m);
        CHET.Adapt(R_p.CHET_R, H.CHET_H, R.CHET_R, etd, MHKS.hk, MSKS.tk, m, m_p);
    }
}
