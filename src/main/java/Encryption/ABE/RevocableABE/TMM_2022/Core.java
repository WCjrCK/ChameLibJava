package Encryption.ABE.RevocableABE.TMM_2022;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.ABEConfig;

public class Core {
    public PublicParam createPublicParam(ABEConfig abeConfig) {
    return new PublicParam(abeConfig);
}

    public void Setup(MasterPublicKey mpk, MasterSecretKey msk, PublicParam pp) {
        pp.FAME.Setup(mpk.FAME_mpk, msk.FAME_msk, pp.FAME_pp);
    }

    public void KeyGen(User user, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st) {
        pp.FAME.KeyGen(user.sk.FAME_sk, pp.FAME_pp, mpk.FAME_mpk, msk.FAME_msk, user.S.toBaseABEAttr());

        int theta = st.Pick(user);
        user.sk.node_id = theta;
        if(!st.tag_g.get(theta)) st.Setg(theta, pp.curve.getRandomPoint(CurveGroup.G1));
        user.sk.sk_theta.put(theta, user.sk.FAME_sk.sk_p[2].div(st.g_theta[theta]));
        while(theta != 0) {
            theta = st.GetFNodeId(theta);
            if(!st.tag_g.get(theta)) st.Setg(theta, pp.curve.getRandomPoint(CurveGroup.G1));
            user.sk.sk_theta.put(theta, user.sk.FAME_sk.sk_p[2].div(st.g_theta[theta]));
        }
        // hide g^d3g^{-rho_p}/g_theta
        user.sk.FAME_sk.sk_p[2] = pp.curve.getRandomPoint(CurveGroup.G1);
    }

    public void KeyUpdate(UpdateKey uk, PublicParam pp, MasterPublicKey mpk, State st, Revocated rl, Info info) {
        st.GetUpdateKeyNode(rl, info);
        uk.info = info;
        Scalar r_theta;
        for(int theta = 0;theta < st.g_theta.length;++theta) {
            if(st.tag.get(theta) && st.tag_g.get(theta)) {
                r_theta = pp.curve.getRandomScalar();
                uk.AddKey(theta,
                        st.g_theta[theta].mul(pp.H(String.valueOf(info.timestamp)).pow(r_theta)),
                        mpk.FAME_mpk.h.pow(r_theta)
                );
            }
        }
    }

    public void DecryptKeyGen(DecryptKey dk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Revocated rl, UpdateKey uk, SecretKey sk) {
        st.GetUpdateKeyNode(rl, uk.info);

        int node_id = sk.node_id, theta = -1;
        if(st.tag.get(node_id)) theta = node_id;
        while(node_id != 0 && theta == -1) {
            node_id = st.GetFNodeId(node_id);
            if(st.tag.get(node_id)) theta = node_id;
        }

        if(theta != -1) {
            dk.CopyFromSK(sk);
            dk.info = uk.info;
            dk.node_id = sk.node_id;

            dk.FAME_sk.sk_p[2] = sk.sk_theta.get(theta).mul(uk.ku_theta_G1.get(theta));
            dk.sk_0_4 = uk.ku_theta_G2.get(theta);
        }
    }

    public void Encrypt(CipherText ct, PublicParam pp, MasterPublicKey mpk, Policy P, PlainText pt, Info info) {
        Scalar s_1 = pp.curve.getRandomScalar();
        Scalar s_2 = pp.curve.getRandomScalar();
        Encrypt(ct, pp, mpk, P, pt, info, s_1, s_2);
    }

    public void Encrypt(CipherText ct, PublicParam pp, MasterPublicKey mpk, Policy P, PlainText pt, Info info, Scalar s_1, Scalar s_2) {
        ct.ct_0_4 = pp.H(String.valueOf(info.timestamp)).pow(s_1.add(s_2));

        MultivePoint ONE_GT = pp.curve.getOne(CurveGroup.GT);

        Encryption.ABE.BaseABE.FAME.PlainText FAME_pt = pp.FAME_pp.createPlainText("");
        FAME_pt.m = ONE_GT.copy();
        pp.FAME.Encrypt(ct.FAME_ct, pp.FAME_pp, mpk.FAME_mpk, P.FAME_p, FAME_pt, s_1, s_2);
        ct.ct = ct.FAME_ct.ct_p.toBytes();
        ct.FAME_ct.ct_p = ONE_GT;

        byte[] tmp = pt.m.toBytes();
        for(int i = 0;i < tmp.length;++i) ct.ct[i] ^= tmp[i];
    }

    public void Decrypt(PlainText pt, PublicParam pp, DecryptKey dk, CipherText ct, Policy P) {
        Encryption.ABE.BaseABE.FAME.PlainText FAME_pt = pp.FAME_pp.createPlainText("");
        pp.FAME.Decrypt(FAME_pt, pp.FAME_pp, dk.FAME_sk, ct.FAME_ct, P.FAME_p);

        byte[] tmp = FAME_pt.m.mul(pp.curve.Pairing(ct.ct_0_4, dk.sk_0_4)).inv().toBytes();
        for(int i = 0;i < tmp.length;++i) tmp[i] ^= ct.ct[i];
        try {
            pt.m = pp.curve.createScalarFromBytes(tmp);
        } catch (RuntimeException e) {
            pt.m = pp.curve.getZeroScalar();
        }
    }

    public void Revoke(Revocated rl, User user, Info info) {
        rl.Add(user, info);
    }
}
