package ChameleonHash.PBCH.MAPBCH.ZLW_2021;

import ChameleonHash.CH.CHET.Components.ETrapdoor;
import ChameleonHash.Interface.MAPBCH;
import ChameleonHash.PBCH.PBCH;
import ChameleonHash.PBCH.PBCHConfig;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;

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
        pp.MAABE.Setup(pp.MAABE_pp);
    }

    @Override
    public void AuthSetup(Authority auth, PublicParam pp) {
        pp.MAABE.AuthSetup(auth.MAABE_auth, pp.MAABE_pp);
    }

    @Override
    public void UserSetup(User user, PublicParam pp) {
        pp.MAABE.UserSetup(user.MAABE_user, pp.MAABE_pp);
    }

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp, Authority auth, Identity id, Attribute attr) {
        pp.MAABE.KeyGen(pk.MAABE_pk, sk.MAABE_sk, pp.MAABE_pp, auth.MAABE_auth, id.MAABE_id, attr.MAABE_attr);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, Identity id, PublicKeyGroup pkg, Policy P, Message m) {
        ETrapdoor etd = pp.CHET_pp.createETrapdoor();
        pp.CHET.Hash(h.CHET_h, r.CHET_r, etd, pp.CHET_pp, pp.CHET_pk, m.CHET_m);

        pp.MAABE.Encrypt(h.MAABE_ct, pp.MAABE_pp, pkg.MAABE_PKG, P.MAABE_P, pp.MAABE_pp.createPlainText(encodeBytes(pp, pp.CHET_pp.serializeETrapdoor(etd))));
    }

    @Override
    public boolean Verify(PublicParam pp, Identity id, PublicKeyGroup pkg, Message m, HashValue h, Randomness r) {
        return pp.CHET.Verify(pp.CHET_pp, pp.CHET_pk, m.CHET_m, h.CHET_h, r.CHET_r);
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, Identity id, PublicKeyGroup pkg, SecretKeyGroup skg, Message m, HashValue h, Randomness r, Message m_p) {
        Encryption.ABE.MAABE.Components.PlainText pt = pp.MAABE_pp.createPlainText("");
        pp.MAABE.Decrypt(pt, pp.MAABE_pp, id.MAABE_id, skg.MAABE_SKG, h.MAABE_ct);

        ETrapdoor etd = pp.CHET_pp.createETrapdoor();
        pp.CHET_pp.deserializeETrapdoor(etd, decodeBytes(pt.toBytes()));

        pp.CHET.Collision(r_p.CHET_r, pp.CHET_pp, pp.CHET_pk, pp.CHET_sk, m.CHET_m, etd, h.CHET_h, r.CHET_r, m_p.CHET_m);
    }
}
