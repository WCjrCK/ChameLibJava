package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import ChameleonHash.CH.DEPRECATED.CH_ET_BC_CDK_2017.Native;
import ChameleonHash.Interface.MAPBCH;
import ChameleonHash.PBCH.PBCH;
import ChameleonHash.PBCH.PBCHConfig;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import Encryption.AES_RAW;
import utils.Hash;

import java.math.BigInteger;

public class Scheme extends PBCH
        implements MAPBCH<
        PublicParam, Authority, User, PublicKeyGroup, PublicKey, SecretKeyGroup, SecretKey,
        Identity, Attribute, Policy, Message, HashValue, Randomness> {
    private byte[] encodeBytes(PublicParam pp, byte[] data) {
        MultivePoint templatePoint = pp.curve.createPoint(CurveGroup.GT);
        byte[] encoded = templatePoint.toBytes();
        int split = encoded.length / 2;
        int cap1 = split - 2;
        int cap2 = encoded.length - split - 2;
        if (data.length > cap1 + cap2)
            throw new IllegalArgumentException("ETrapdoor 序列化结果过长，无法编码进 GT 元素");

        int l1 = Math.min(data.length, cap1);
        int l2 = data.length - l1;
        if (l2 > cap2) {
            l2 = cap2;
            l1 = data.length - l2;
        }

        encoded[1] = (byte) l1;
        encoded[split + 1] = (byte) l2;
        System.arraycopy(data, 0, encoded, 2, l1);
        System.arraycopy(data, l1, encoded, split + 2, l2);
        return encoded;
    }

    private byte[] decodeBytes(byte[] data) {
        int split = data.length / 2;
        int l1 = Byte.toUnsignedInt(data[1]);
        int l2 = Byte.toUnsignedInt(data[split + 1]);
        int cap1 = split - 2;
        int cap2 = data.length - split - 2;
        if (l1 > cap1 || l2 > cap2) throw new RuntimeException("GT 解码失败");

        byte[] res = new byte[l1 + l2];
        System.arraycopy(data, 2, res, 0, l1);
        System.arraycopy(data, split + 2, res, l1, l2);
        return res;
    }

    @Override
    public PublicParam createPublicParam(PBCHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(PublicParam pp) {
        pp.CHET.Setup(pp.CHET_pp);
        pp.CHET.KeyGen(pp.CHET_pk, pp.CHET_sk, pp.CHET_pp);
        pp.DS.Setup(pp.DS_pp);
        pp.DS.KeyGen(pp.DS_pk, pp.DS_sk, pp.DS_pp);
        pp.MAABE.Setup(pp.MAABE_pp);
    }

    @Override
    public void AuthSetup(Authority auth, PublicParam pp) {
        pp.MAABE.AuthSetup(auth.MAABE_auth, pp.MAABE_pp);
    }

    @Override
    public void UserSetup(User user, PublicParam pp) {
        DS.Sign(mod.sigma_gid, sk.sk_DS, pp.pp_DS, "1" + mod.gid);
        mod.sk_gid = sk.sk_CH;
    }

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp, Authority auth, Identity id, Attribute attr) {
        if(!DS.Verify(pp.pp_DS, pk.pk_DS, mod.sigma_gid, "1" + mod.gid)) throw new RuntimeException("illegal signature");
        MA_ABE.KeyGen(auth.MA_ABE_Auth, mod.sk_gid_A, A, pp.GP_MA_ABE, "0" + mod.gid);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, Identity id, PublicKeyGroup pkg, Policy P, Message m) {
        Native.ETrapdoor etd = new Native.ETrapdoor();
        CH_ET.Hash(H.h, R.r, etd, pk.pk_CH, m);
        byte[] r_t = new byte[16];
        rand.nextBytes(r_t);
        byte[] k = new byte[16];
        rand.nextBytes(k);
        AES_RAW.PlainText pt_SE = new AES_RAW.PlainText();
        pt_SE.pt = etd.sk_ch_2.d.toByteArray();
        AES_RAW.Encrypt(H.c_SE, pt_SE, k);

        Hash.EncText enc = new Hash.EncText();
        Hash.Encode(enc, pp.GP_MA_ABE.GP.GT, new Hash.PlaText(k, r_t));
        ABE.MA_ABE.PBC.PlainText pt_MA_ABE = new ABE.MA_ABE.PBC.PlainText(enc.K);
        genEncMAABE(H.c_MA_ABE, pt_MA_ABE, PKG, MSP, pp, r_t);
    }

    @Override
    public boolean Verify(PublicParam pp, Identity id, PublicKeyGroup pkg, Message m, HashValue h, Randomness r) {
        return pp.CHET.Verify(pp.CHET_pp, pp.CHET_pk, m.CHET_m, h.CHET_h, r.CHET_r);
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, Identity id, PublicKeyGroup pkg, SecretKeyGroup skg, Message m, HashValue h, Randomness r, Message m_p) {
        ABE.MA_ABE.PBC.PlainText pt_MA_ABE = new ABE.MA_ABE.PBC.PlainText(pp.GP_MA_ABE.GP.GetGTElement());
        ABE.MA_ABE.PBC.CipherText ct_MA_ABE = new ABE.MA_ABE.PBC.CipherText();
        MA_ABE.Decrypt(pt_MA_ABE, pp.GP_MA_ABE, SKG.MA_ABE_SKG, MSP, H.c_MA_ABE);
        Hash.PlaText pla = new Hash.PlaText();
        Hash.Decode(pla, new Hash.EncText(pt_MA_ABE.m));
        genEncMAABE(ct_MA_ABE, pt_MA_ABE, PKG, MSP, pp, pla.r);
        if(!ct_MA_ABE.isEqual(H.c_MA_ABE)) throw new RuntimeException("illegal decrypt");

        Native.ETrapdoor etd = new Native.ETrapdoor();

        AES_RAW.PlainText pt_SE = new AES_RAW.PlainText();
        AES_RAW.Decrypt(pt_SE, H.c_SE, pla.k);
        etd.sk_ch_2.d = new BigInteger(pt_SE.pt);
        CH_ET.Adapt(R_p.r, H.h, R.r, etd, pk.pk_CH, sk.sk_CH, m, m_p);
    }
}
