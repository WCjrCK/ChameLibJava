package ChameleonHash.PBCH.BasePBCH.DSS_2019;

import ChameleonHash.CH.CHET.Components.ETrapdoor;
import ChameleonHash.Interface.BasePBCH;
import ChameleonHash.PBCH.PBCHConfig;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.BaseABE.FAME.CipherText;
import Encryption.ABE.BaseABE.FAME.PlainText;

import java.util.Arrays;

public class Scheme
        extends ChameleonHash.PBCH.BasePBCH.Scheme<PublicParam, MasterPublicKey, MasterSecretKey, SecretKey, Policy, Attributes, Message, HashValue, Randomness>
        implements BasePBCH<PublicParam, MasterPublicKey, MasterSecretKey, SecretKey, Policy, Attributes, Message, HashValue, Randomness> {
    @Override
    public PublicParam createPublicParam(PBCHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk) {
        pp.SEScheme.Setup(pp.SE_pp);
        pp.CHETScheme.Setup(pp.CHET_pp);
        pp.CHETScheme.KeyGen(mpk.CHET_pk, msk.CHET_sk, pp.CHET_pp);
        pp.FAME.Setup(mpk.FAME_mpk, msk.FAME_msk, pp.FAME_pp);
    }

    @Override
    public void KeyGen(SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, Attributes S) {
        sk.CHET_sk = msk.CHET_sk;
        pp.FAME.KeyGen(sk.FAME_sk, pp.FAME_pp, mpk.FAME_mpk, msk.FAME_msk, S.A);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, MasterPublicKey mpk, Message m, Policy P) {
        ETrapdoor etd = pp.CHET_pp.createETrapdoor();
        pp.CHETScheme.Hash(h.CHET_h, r.CHET_r, pp.CHET_pp, mpk.CHET_pk, m.CHET_m, etd);
        byte[] rb = new byte[16];
        pp.rand.nextBytes(rb);
        byte[] kb = new byte[16];
        pp.rand.nextBytes(kb);

        Scalar u_1 = pp.H(Arrays.toString(rb) + "|" + P.P.MSP.formula);
        Scalar u_2 = pp.H(P.P.MSP.formula + "|" + Arrays.toString(rb));

        PlainText FAME_pt = new PlainText();
        FAME_pt.m = pp.curve.createPoint(CurveGroup.GT);
        byte[] tmp = FAME_pt.m.toBytes();
        tmp[1] = (byte) kb.length;
        System.arraycopy(kb, 0, tmp, 2, kb.length);
        tmp[tmp.length / 2 + 1] = (byte) rb.length;
        System.arraycopy(rb, 0, tmp, tmp.length / 2 + 2, rb.length);
        FAME_pt.m = pp.curve.createPointFromBytes(CurveGroup.GT, tmp);

        pp.FAME.Encrypt(h.FAME_ct, pp.FAME_pp, mpk.FAME_mpk, P.P, FAME_pt, u_1, u_2);
        pp.SEScheme.Encrypt(h.SE_ct, pp.SE_pp, pp.SE_pp.createSecretKey(kb), pp.SE_pp.createPlainText(pp.CHET_pp.serializeETrapdoor(etd)));
    }

    @Override
    public boolean Verify(PublicParam pp, MasterPublicKey mpk, Message m, HashValue h, Randomness r) {
        return pp.CHETScheme.Verify(pp.CHET_pp, mpk.CHET_pk, m.CHET_m, h.CHET_h, r.CHET_r);
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, MasterPublicKey mpk, SecretKey sk, Message m, Policy P, HashValue h, Randomness r, Message m_p) {
        PlainText FAME_pt = pp.FAME_pp.createPlainText("");
        pp.FAME.Decrypt(FAME_pt, pp.FAME_pp, mpk.FAME_mpk, sk.FAME_sk, h.FAME_ct, P.P);
        byte[] tmp = FAME_pt.m.toBytes();
        int l1 = tmp[1];
        if(l1 < 0 || l1 + 2 >= tmp.length) throw new RuntimeException("解码失败");
        byte[] kb = new byte[l1];
        System.arraycopy(tmp, 2, kb, 0, l1);
        int l2 = tmp[tmp.length / 2 + 1];
        if(l2 < 0 || l2 + tmp.length / 2 + 2 >= tmp.length) throw new RuntimeException("解码失败");
        byte[] rb = new byte[l2];
        System.arraycopy(tmp, tmp.length / 2 + 2, rb, 0, l2);

        Scalar u_1 = pp.H(Arrays.toString(rb) + "|" + P.P.MSP.formula);
        Scalar u_2 = pp.H(P.P.MSP.formula + "|" + Arrays.toString(rb));

        CipherText FAME_ct = pp.FAME_pp.createCipherText();
        pp.FAME.Encrypt(FAME_ct, pp.FAME_pp, mpk.FAME_mpk, P.P, FAME_pt, u_1, u_2);

        if(!FAME_ct.isEqual(h.FAME_ct)) throw new RuntimeException("FAME 密文有误");
        Encryption.SE.Components.PlainText SE_pt = pp.SE_pp.createPlainText("");
        pp.SEScheme.Decrypt(SE_pt, pp.SE_pp, pp.SE_pp.createSecretKey(kb), h.SE_ct);

        ETrapdoor etd = pp.CHET_pp.createETrapdoor();
        pp.CHET_pp.deserializeETrapdoor(etd, SE_pt.getBytes());

        pp.CHETScheme.Collision(r_p.CHET_r, pp.CHET_pp, mpk.CHET_pk, sk.CHET_sk, m.CHET_m, etd, h.CHET_h, r.CHET_r, m_p.CHET_m);
    }
}
