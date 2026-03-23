package Encryption.ABE.RevocableABE.XNM_2021;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.RevocableABE.Components.Attributes;

public class Core {
    public PublicParam createPublicParam(ABEConfig abeConfig) {
        return new PublicParam(abeConfig);
    }

    public void Setup(MasterPublicKey mpk, MasterSecretKey msk, PublicParam pp) {
        pp.FAME.Setup(mpk.FAME_mpk, msk.FAME_msk, pp.FAME_pp);
    }

    public void KeyGen(SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Identity id, Attributes S) {
        pp.FAME.KeyGen(sk.FAME_sk, pp.FAME_pp, mpk.FAME_mpk, msk.FAME_msk, S.toBaseABEAttr());

        int theta = st.Pick(id);
        sk.node_id = theta;
        if(!st.tag_g.get(theta)) st.Setg(theta, pp.curve.getRandomPoint(CurveGroup.G1));
        sk.sk_theta.put(theta, sk.FAME_sk.sk_p[2].div(st.g_theta[theta]));
        while(theta != 0) {
            theta = st.GetFNodeId(theta);
            if(!st.tag_g.get(theta)) st.Setg(theta, pp.curve.getRandomPoint(CurveGroup.G1));
            sk.sk_theta.put(theta, sk.FAME_sk.sk_p[2].div(st.g_theta[theta]));
        }
        // hide g^d3g^{-rho_p}/g_theta
        sk.FAME_sk.sk_p[2] = pp.curve.getRandomPoint(CurveGroup.G1);
    }

    public void KeyUpdate(State st, PublicParam pp, MasterPublicKey mpk, Info info) {
        st.GetUpdateKeyNode(st.rl, info);
        st.uk.info = info;
        Scalar r_theta;
        for(int theta = 0;theta < st.g_theta.length;++theta) {
            if(st.tag.get(theta) && st.tag_g.get(theta)) {
                r_theta = pp.curve.getRandomScalar();
                st.uk.AddKey(theta,
                        st.g_theta[theta].mul(pp.H(String.valueOf(info.timestamp)).pow(r_theta)),
                        mpk.FAME_mpk.h.pow(r_theta)
                );
            }
        }
    }

    public void DecryptKeyGen(SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st) {
        st.GetUpdateKeyNode(st.rl, st.uk.info);

        int node_id = sk.node_id, theta = -1;
        if(st.tag.get(node_id)) theta = node_id;
        while(node_id != 0 && theta == -1) {
            node_id = st.GetFNodeId(node_id);
            if(st.tag.get(node_id)) theta = node_id;
        }

        if(theta != -1) {
            sk.dk.CopyFromSK(sk);
            sk.dk.info = st.uk.info;
            sk.dk.node_id = sk.node_id;
            MultivePoint ku_theta_0 = st.uk.ku_theta_G1.get(theta);
            MultivePoint ku_theta_1 = st.uk.ku_theta_G2.get(theta);
            Scalar r_theta_p = pp.curve.getRandomScalar();
            sk.dk.FAME_sk.sk_p[2] = sk.sk_theta.get(theta).mul(ku_theta_0).mul(pp.H(String.valueOf(sk.dk.info.timestamp)).pow(r_theta_p));
            sk.dk.sk_0_4 = ku_theta_1.mul(mpk.FAME_mpk.h.pow(r_theta_p));
        }
    }

    public void Encrypt(CipherText ct, PublicParam pp, MasterPublicKey mpk, Policy P, PlainText pt, Info info) {
        Scalar s_1 = pp.curve.getRandomScalar();
        Scalar s_2 = pp.curve.getRandomScalar();
        Encrypt(ct, pp, mpk, P, pt, info, s_1, s_2);
    }

    public void Encrypt(CipherText ct, PublicParam pp, MasterPublicKey mpk, Policy P, PlainText pt, Info info, Scalar s_1, Scalar s_2) {
        ct.ct_0_4 = pp.H(String.valueOf(info.timestamp)).pow(s_1.add(s_2));
        pp.FAME.Encrypt(ct.FAME_ct, pp.FAME_pp, mpk.FAME_mpk, P.FAME_p, pt.FAME_pt, s_1, s_2);
    }

    public void Decrypt(PlainText pt, PublicParam pp, SecretKey sk, CipherText ct) {
        pp.FAME.Decrypt(pt.FAME_pt, pp.FAME_pp, sk.dk.FAME_sk, ct.FAME_ct);
        pt.FAME_pt.m = pt.FAME_pt.m.mul(pp.curve.Pairing(ct.ct_0_4, sk.dk.sk_0_4));
    }

    public void Revoke(State st, Identity id, Info info) {
        st.rl.Add(id, info);
    }
}
