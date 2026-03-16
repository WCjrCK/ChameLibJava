package ChameleonHash.PBCH.BasePBCH.DSS_2019;

import ChameleonHash.CH.CHET.Components.ETrapdoor;
import ChameleonHash.Interface.BasePBCH;
import ChameleonHash.PBCH.PBCH;
import ChameleonHash.PBCH.PBCHConfig;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.FAME.PlainText;

import java.util.Arrays;

public class Scheme
        extends PBCH<PublicParam, MasterPublicKey, MasterSecretKey, SecretKey, Policy, Attributes, Message, HashValue, Randomness>
        implements BasePBCH<PublicParam, MasterPublicKey, MasterSecretKey, SecretKey, Policy, Attributes, Message, HashValue, Randomness> {
    @Override
    public PublicParam createPublicParam(PBCHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk) {
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

        Scalar u_1 = pp.H(Arrays.toString(rb) + "|" + P.P.formula);
        Scalar u_2 = pp.H(P.P.formula + "|" + Arrays.toString(rb));

        PlainText FAME_pt = new PlainText();
        FAME_pt.m = pp.curve.createPoint(CurveGroup.GT);
        byte[] tmp = FAME_pt.m.toBytes();
        tmp[1] = (byte) kb.length;
        System.arraycopy(kb, 0, tmp, 2, kb.length);
        tmp[tmp.length / 2 + 1] = (byte) rb.length;
        System.arraycopy(rb, 0, tmp, tmp.length / 2 + 2, rb.length);
        FAME_pt.m = pp.curve.createPointFromBytes(CurveGroup.GT, tmp);

        pp.FAME.Encrypt(h.FAME_ct, pp.FAME_pp, mpk.FAME_mpk, P.P, FAME_pt, u_1, u_2);

//        AES_RAW.Encrypt(h.SE_ct, new AES_RAW.PlainText(etd.sk_ch_2.d.toByteArray()), kb);
//
//        pp.SEScheme.Encrypt(h.SE_ct, pp.SE_pp, kb, pt);
    }

    @Override
    public boolean Verify(PublicParam pp, MasterPublicKey mpk, Message m, HashValue h, Randomness r) {
        return pp.CHETScheme.Verify(pp.CHET_pp, mpk.CHET_pk, m.CHET_m, h.CHET_h, r.CHET_r);
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, MasterPublicKey mpk, SecretKey sk, Message m, HashValue h, Randomness r, Message m_p) {

    }
}
