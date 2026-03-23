package ChameleonHash.PBCH.RevocablePBCH.XNM_2021;

import ChameleonHash.CH.CHET.Components.ETrapdoor;
import ChameleonHash.Interface.RevocablePBCH;
import ChameleonHash.PBCH.PBCH;
import ChameleonHash.PBCH.PBCHConfig;
import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.RevocableABE.XNM_2021.CipherText;
import Encryption.ABE.RevocableABE.XNM_2021.PlainText;

import java.util.Arrays;

/*
 * Revocable Policy-Based Chameleon Hash
 * P13. 5.2 Proposed RPCH
 */

public class Scheme extends PBCH
        implements RevocablePBCH<
                PublicParam, MasterPublicKey, MasterSecretKey, State, Revocated, UpdateKey,
                PublicKey, SecretKey, DecryptKey, Identity, Attributes, Info, Policy, Message, HashValue, Randomness
                >{
    @Override
    public PublicParam createPublicParam(PBCHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk) {
        pp.CHET.Setup(pp.CHET_pp);
        pp.CHET.KeyGen(mpk.CHET_pk, msk.CHET_sk, pp.CHET_pp);
        pp.RABE.Setup(mpk.RABE_mpk, msk.RABE_msk, pp.RABE_pp);
    }

//    @Override
//    public void AssignUser(User user, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk) {
////        pp.RABE.
//    }

    @Override
    public void KeyGen(SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Revocated rl, Identity id, UpdateKey uk, DecryptKey dk, Attributes S) {
        pp.RABE.KeyGen(sk.RABE_sk, pp.RABE_pp, mpk.RABE_mpk, msk.RABE_msk, st.RABE_st, id.RABE_id, S.toRABEAttr());
        sk.CHET_sk.CopyFrom(msk.CHET_sk);
    }

    @Override
    public void KeyUpdate(UpdateKey uk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Revocated rl, Info info) {
        pp.RABE.KeyUpdate(st.RABE_st, pp.RABE_pp, mpk.RABE_mpk, info.RABE_info);
    }

    @Override
    public void DecryptKeyGen(DecryptKey dk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Revocated rl, UpdateKey uk, SecretKey sk, Attributes S) {
        pp.RABE.DecryptKeyGen(sk.RABE_sk, pp.RABE_pp, mpk.RABE_mpk, msk.RABE_msk, st.RABE_st);
        dk.info.RABE_info = dk.RABE_dk.info;
        dk.CHET_sk.CopyFrom(sk.CHET_sk);
    }

    @Override
    public void Revoke(Revocated rl, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Identity id, Info info) {
        pp.RABE.Revoke(st.RABE_st, id.RABE_id, info.RABE_info);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, MasterPublicKey mpk, Identity id, PublicKey pk, Message m, Policy P, Info info) {
        ETrapdoor etd = pp.CHET_pp.createETrapdoor();
        pp.CHET.Hash(h.CHET_h, r.CHET_r, etd, pp.CHET_pp, mpk.CHET_pk, m.CHET_m);
        byte[] rb = new byte[16];
        pp.rand.nextBytes(rb);
        byte[] kb = new byte[16];
        pp.rand.nextBytes(kb);

        Scalar u_1 = pp.H(Arrays.toString(rb) + "|" + P.RABE_P.FAME_p.MSP.formula + "|" + Arrays.toString(pp.serializeInfo(info)));
        Scalar u_2 = pp.H(Arrays.toString(pp.serializeInfo(info)) + "|" + P.RABE_P.FAME_p.MSP.formula + "|" + Arrays.toString(rb));

        PlainText RABE_pt = pp.RABE_pp.createPlainText("");
        RABE_pt.FAME_pt.m = pp.curve.createPoint(CurveGroup.GT);
        byte[] tmp = RABE_pt.FAME_pt.m.toBytes();
        tmp[1] = (byte) kb.length;
        System.arraycopy(kb, 0, tmp, 2, kb.length);
        tmp[tmp.length / 2 + 1] = (byte) rb.length;
        RABE_pt.FAME_pt.m = pp.curve.createPointFromBytes(CurveGroup.GT, tmp);

        pp.RABE.Encrypt(h.RABE_ct, pp.RABE_pp, mpk.RABE_mpk, P.RABE_P, RABE_pt, info.RABE_info, u_1, u_2);

        pp.SE.Encrypt(h.SE_ct, pp.SE_pp, pp.SE_pp.createSecretKey(kb), pp.SE_pp.createPlainText(pp.CHET_pp.serializeETrapdoor(etd)));
    }

    @Override
    public boolean Verify(PublicParam pp, MasterPublicKey mpk, PublicKey pk, Message m, HashValue h, Randomness r) {
        return pp.CHET.Verify(pp.CHET_pp, mpk.CHET_pk, m.CHET_m, h.CHET_h, r.CHET_r);
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, MasterPublicKey mpk, PublicKey pk, SecretKey sk, DecryptKey dk, Message m, Policy P, HashValue h, Randomness r, Message m_p) {
        PlainText RABE_pt = pp.RABE_pp.createPlainText("");
        pp.RABE.Decrypt(RABE_pt, pp.RABE_pp, sk.RABE_sk, h.RABE_ct);
        byte[] tmp = RABE_pt.FAME_pt.m.toBytes();
        int l1 = tmp[1];
        if(l1 < 0 || l1 + 2 >= tmp.length) throw new RuntimeException("解码失败");
        byte[] kb = new byte[l1];
        System.arraycopy(tmp, 2, kb, 0, l1);
        int l2 = tmp[tmp.length / 2 + 1];
        if(l2 < 0 || l2 + tmp.length / 2 + 2 >= tmp.length) throw new RuntimeException("解码失败");
        byte[] rb = new byte[l2];
        System.arraycopy(tmp, tmp.length / 2 + 2, rb, 0, l2);

        Scalar u_1 = pp.H(Arrays.toString(rb) + "|" + P.RABE_P.FAME_p.MSP.formula + "|" + Arrays.toString(pp.serializeInfo(dk.info)));
        Scalar u_2 = pp.H(Arrays.toString(pp.serializeInfo(dk.info)) + "|" + P.RABE_P.FAME_p.MSP.formula + "|" + Arrays.toString(rb));


        CipherText RABE_ct = pp.RABE_pp.createCipherText();
        pp.RABE.Encrypt(RABE_ct, pp.RABE_pp, mpk.RABE_mpk, P.RABE_P, RABE_pt, dk.RABE_dk.info, u_1, u_2);

        if(!RABE_ct.isEqual(h.RABE_ct)) throw new RuntimeException("RABE 密文有误");
        Encryption.SE.Components.PlainText SE_pt = pp.SE_pp.createPlainText("");
        pp.SE.Decrypt(SE_pt, pp.SE_pp, pp.SE_pp.createSecretKey(kb), h.SE_ct);

        ETrapdoor etd = pp.CHET_pp.createETrapdoor();
        pp.CHET_pp.deserializeETrapdoor(etd, SE_pt.getBytes());

        pp.CHET.Collision(r_p.CHET_r, pp.CHET_pp, mpk.CHET_pk, sk.CHET_sk, m.CHET_m, etd, h.CHET_h, r.CHET_r, m_p.CHET_m);
    }
}
