package ChameleonHash.PBCH.RevocablePBCH.TMM_2022;

import ChameleonHash.Interface.RevocablePBCH;
import ChameleonHash.PBCH.PBCH;
import ChameleonHash.PBCH.PBCHConfig;
import Encryption.ABE.RevocableABE.TMM_2022.PlainText;

/*
 * Revocable Policy-Based Chameleon Hash
 * P13. 5.2 Proposed RPCH
 */

public class Scheme extends PBCH
        implements RevocablePBCH<
        PublicParam, MasterPublicKey, MasterSecretKey, State, PublicKey,
        SecretKey, Identity, Attributes, Info, Policy, Message, HashValue, Randomness
                >{
    @Override
    public PublicParam createPublicParam(PBCHConfig config) {
        return new PublicParam(config);
    }

    @Override
    public void Setup(PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk) {
        mpk.g = pp.curve.getRandomPoint(pp.curveGroup);
        pp.RABE.Setup(mpk.RABE_mpk, msk.RABE_msk, pp.RABE_pp);
    }

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Identity id, Attributes S) {
        pp.RABE.KeyGen(sk.RABE_sk, pp.RABE_pp, mpk.RABE_mpk, msk.RABE_msk, st.RABE_st, id.RABE_id, S.toRABEAttr());
        sk.x = pp.curve.getRandomScalar();
        pk.pk = mpk.g.pow(sk.x);
    }

    @Override
    public void KeyUpdate(State st, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, Info info) {
        pp.RABE.KeyUpdate(st.RABE_st, pp.RABE_pp, mpk.RABE_mpk, info.RABE_info);
    }

    @Override
    public void DecryptKeyGen(SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st) {
        pp.RABE.DecryptKeyGen(sk.RABE_sk, st.RABE_st);
    }

    @Override
    public void Revoke(State st, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, Identity id, Info info) {
        pp.RABE.Revoke(st.RABE_st, id.RABE_id, info.RABE_info);
    }

    @Override
    public void Hash(HashValue h, Randomness r, PublicParam pp, MasterPublicKey mpk, PublicKey pk, Identity id, Message m, Policy P, Info info) {
        PlainText RABE_pt = pp.RABE_pp.createPlainText("");
        RABE_pt.m = pp.curve.getRandomScalar();
        r.r = pp.curve.getRandomScalar();
        h.h = mpk.g.pow(RABE_pt.m);
        h.b = pk.pk.pow(m.m).mul(h.h.pow(r.r));
        pp.RABE.Encrypt(h.RABE_ct, pp.RABE_pp, mpk.RABE_mpk, P.RABE_P, RABE_pt, info.RABE_info);
    }

    @Override
    public boolean Verify(PublicParam pp, MasterPublicKey mpk, PublicKey pk, Message m, HashValue h, Randomness r) {
        return h.b.isEqual(pk.pk.pow(m.m).mul(h.h.pow(r.r)));
    }

    @Override
    public void Collision(Randomness r_p, PublicParam pp, MasterPublicKey mpk, PublicKey pk, SecretKey sk, Message m, HashValue h, Randomness r, Message m_p) {
        PlainText RABE_pt = pp.RABE_pp.createPlainText("");
        pp.RABE.Decrypt(RABE_pt, pp.RABE_pp, sk.RABE_sk, h.RABE_ct);
        r_p.r = r.r.add(m.m.sub(m_p.m).mul(sk.x.div(RABE_pt.m)));
    }
}
