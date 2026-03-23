package ChameleonHash.PBCH.MAPBCH.MXN_2022;

import ChameleonHash.CH.CHET.Components.ETrapdoor;
import ChameleonHash.Interface.MAPBCH;
import ChameleonHash.PBCH.PBCH;
import ChameleonHash.PBCH.PBCHConfig;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.MAABE.RW_2015.Core;
import Encryption.SE.Components.PlainText;

import java.security.SecureRandom;
import java.util.Arrays;

public class Scheme extends PBCH
        implements MAPBCH<
        PublicParam, Authority, User, PublicKeyGroup, PublicKey, SecretKeyGroup, SecretKey,
        Identity, Attribute, Policy, Message, HashValue, Randomness> {
    private final SecureRandom rand = new SecureRandom();
    private final Core maabeCore = new Core();

    private byte[] encodeSplitBytes(PublicParam pp, byte[] left, byte[] right) {
        byte[] encoded = pp.curve.getZero(CurveGroup.GT).toBytes();
        int split = encoded.length / 2;
        int cap1 = split - 2;
        int cap2 = encoded.length - split - 2;
        if (left.length > cap1 || right.length > cap2)
            throw new IllegalArgumentException("随机盐或对称密钥过长，无法编码进 GT 元素");

        encoded[1] = (byte) left.length;
        System.arraycopy(left, 0, encoded, 2, left.length);
        encoded[split + 1] = (byte) right.length;
        System.arraycopy(right, 0, encoded, split + 2, right.length);
        return encoded;
    }

    private byte[][] decodeSplitBytes(byte[] data) {
        int split = data.length / 2;
        int l1 = Byte.toUnsignedInt(data[1]);
        int l2 = Byte.toUnsignedInt(data[split + 1]);
        int cap1 = split - 2;
        int cap2 = data.length - split - 2;
        if (l1 > cap1 || l2 > cap2) throw new RuntimeException("GT 解码失败");

        byte[] left = new byte[l1];
        System.arraycopy(data, 2, left, 0, l1);
        byte[] right = new byte[l2];
        System.arraycopy(data, split + 2, right, 0, l2);
        return new byte[][]{left, right};
    }

    private void deterministicEncrypt(
            Encryption.ABE.MAABE.RW_2015.CipherText ct,
            PublicParam pp,
            PublicKeyGroup pkg,
            Encryption.ABE.MAABE.RW_2015.Policy P,
            Encryption.ABE.MAABE.RW_2015.PlainText pt,
            byte[] r_t
    ) {
        int rows = P.MSP.M.length;
        int cols = P.MSP.M[0].length;
        String seed = Arrays.toString(r_t);
        String formula = P.MSP.formula;

        Scalar[] t_x = new Scalar[rows];
        for (int i = 1; i <= rows; ++i) t_x[i - 1] = pp.H(String.format("%s%s0%d", seed, formula, i));

        Scalar[] v = new Scalar[cols];
        v[0] = pp.H(String.format("%s%s", seed, formula));
        for (int i = 2; i <= cols; ++i) v[i - 1] = pp.H(String.format("%s%s1%d", seed, formula, i));

        Scalar[] w = new Scalar[cols];
        w[0] = pp.MAABE_pp.curve.getZeroScalar();
        for (int i = 2; i <= cols; ++i) w[i - 1] = pp.H(String.format("%s%s2%d", seed, formula, i));

        maabeCore.Encrypt(ct, pp.MAABE_pp, pkg.MAABE_PKG, P, pt, v, w, t_x);
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
        pp.DS.Sign(user.DS_sigma_gid, pp.DS_pp, pp.DS_sk, pp.DS_pp.createMessage("1" + user.gid));
    }

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp, Authority auth, Identity id, Attribute attr) {
        if (!pp.DS.Verify(pp.DS_pp, pp.DS_pk, id.DS_sigma_gid, pp.DS_pp.createMessage("1" + id.id)))
            throw new RuntimeException("签名不正确");
        pp.MAABE.KeyGen(pk.MAABE_pk, sk.MAABE_sk, pp.MAABE_pp, auth.MAABE_auth, id.MAABE_id, attr.MAABE_attr);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, Identity id, PublicKeyGroup pkg, Policy P, Message m) {
        ETrapdoor etd = pp.CHET_pp.createETrapdoor();
        pp.CHET.Hash(h.CHET_h, r.CHET_r, etd, pp.CHET_pp, pp.CHET_pk, m.CHET_m);

        byte[] r_t = new byte[16];
        rand.nextBytes(r_t);
        byte[] k = new byte[16];
        rand.nextBytes(k);

        pp.SE.Encrypt(h.SE_ct, pp.SE_pp, pp.SE_pp.createSecretKey(k), pp.SE_pp.createPlainText(pp.CHET_pp.serializeETrapdoor(etd)));

        Encryption.ABE.MAABE.RW_2015.PlainText pt = pp.MAABE_pp.createPlainText(encodeSplitBytes(pp, k, r_t));
        deterministicEncrypt(h.MAABE_ct, pp, pkg, P.MAABE_P, pt, r_t);
    }

    @Override
    public boolean Verify(PublicParam pp, Identity id, PublicKeyGroup pkg, Message m, HashValue h, Randomness r) {
        return pp.CHET.Verify(pp.CHET_pp, pp.CHET_pk, m.CHET_m, h.CHET_h, r.CHET_r);
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, Identity id, PublicKeyGroup pkg, SecretKeyGroup skg, Message m, HashValue h, Randomness r, Message m_p) {
        if (Arrays.equals(pp.CHET_pp.serializeMessage(m.CHET_m), pp.CHET_pp.serializeMessage(m_p.CHET_m))) {
            pp.CHET_pp.deserializeRandomness(r_p.CHET_r, pp.CHET_pp.serializeRandomness(r.CHET_r));
            return;
        }

        Encryption.ABE.MAABE.RW_2015.PlainText pt = pp.MAABE_pp.createPlainText("");
        pp.MAABE.Decrypt(pt, pp.MAABE_pp, id.MAABE_id, skg.MAABE_SKG, h.MAABE_ct);

        byte[][] decoded = decodeSplitBytes(pt.toBytes());
        byte[] k = decoded[0];
        byte[] r_t = decoded[1];

        Encryption.ABE.MAABE.RW_2015.CipherText ct = pp.MAABE_pp.createCipherText();
        deterministicEncrypt(ct, pp, pkg, h.MAABE_ct.P, pp.MAABE_pp.createPlainText(encodeSplitBytes(pp, k, r_t)), r_t);
        if (!ct.isEqual(h.MAABE_ct)) throw new RuntimeException("MAABE重加密错误");

        PlainText SE_pt = pp.SE_pp.createPlainText("");
        pp.SE.Decrypt(SE_pt, pp.SE_pp, pp.SE_pp.createSecretKey(k), h.SE_ct);

        ETrapdoor etd = pp.CHET_pp.createETrapdoor();
        pp.CHET_pp.deserializeETrapdoor(etd, SE_pt.getBytes());

        pp.CHET.Collision(r_p.CHET_r, pp.CHET_pp, pp.CHET_pk, pp.CHET_sk, m.CHET_m, etd, h.CHET_h, r.CHET_r, m_p.CHET_m);
    }
}
