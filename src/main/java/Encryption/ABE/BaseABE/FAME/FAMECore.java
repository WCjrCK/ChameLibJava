package Encryption.ABE.BaseABE.FAME;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.Components.Attributes;

import java.util.HashMap;

public class FAMECore {
    public PublicParam createPublicParam(ABEConfig abeConfig) {
        return new PublicParam(abeConfig);
    }

    public void Setup(MasterPublicKey mpk, MasterSecretKey msk, PublicParam pp) {
        Scalar d_1 = pp.curve.getRandomScalar();
        Scalar d_2 = pp.curve.getRandomScalar();
        Scalar d_3 = pp.curve.getRandomScalar();
        mpk.h = pp.curve.getRandomPoint(CurveGroup.G2);

        mpk.g = pp.curve.getRandomPoint(CurveGroup.G1);

        MultivePoint egh = pp.curve.Pairing(mpk.g, mpk.h);

        msk.a_1 = pp.curve.getRandomScalar();
        msk.a_2 = pp.curve.getRandomScalar();
        msk.b_1 = pp.curve.getRandomScalar();
        msk.b_2 = pp.curve.getRandomScalar();

        mpk.H_1 = mpk.h.pow(msk.a_1);
        mpk.H_2 = mpk.h.pow(msk.a_2);
        mpk.T_1 = egh.pow(d_1.mul(msk.a_1).add(d_3));
        mpk.T_2 = egh.pow(d_2.mul(msk.a_2).add(d_3));

        msk.g_d1 = mpk.g.pow(d_1);
        msk.g_d2 = mpk.g.pow(d_2);
        msk.g_d3 = mpk.g.pow(d_3);
    }
    
    public void Setup(MasterPublicKey mpk, MasterSecretKey msk, PublicParam pp, Scalar d_1, Scalar d_2, Scalar d_3, Scalar alpha) {
        mpk.h = pp.curve.getRandomPoint(CurveGroup.G2);

        mpk.g = pp.curve.getRandomPoint(CurveGroup.G1);

        MultivePoint egh = pp.curve.Pairing(mpk.g, mpk.h);

        msk.a_1 = pp.curve.getRandomScalar();
        msk.a_2 = pp.curve.getRandomScalar();
        msk.b_1 = pp.curve.getRandomScalar();
        msk.b_2 = pp.curve.getRandomScalar();

        mpk.H_1 = mpk.h.pow(msk.a_1);
        mpk.H_2 = mpk.h.pow(msk.a_2);
        mpk.T_1 = egh.pow(d_1.mul(msk.a_1).add(d_3.div(alpha)));
        mpk.T_2 = egh.pow(d_2.mul(msk.a_2).add(d_3.div(alpha)));

        msk.g_d1 = mpk.g.pow(d_1);
        msk.g_d2 = mpk.g.pow(d_2);
        msk.g_d3 = mpk.g.pow(d_3);
    }

    public void KeyGen(SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, Attributes S) {
        Scalar r_1 = pp.curve.getRandomScalar();
        Scalar r_2 = pp.curve.getRandomScalar();
        sk.Attr2id = new HashMap<>();
        sk.S.attrs.addAll(S.attrs);
        sk.sk_y = new MultivePoint[S.attrs.size()][3];

        Scalar b1r1a1 = msk.b_1.mul(r_1);
        sk.sk_0[0] = mpk.h.pow(b1r1a1);
        Scalar b1r1a2 = b1r1a1.div(msk.a_2);
        b1r1a1 = b1r1a1.div(msk.a_1);
        Scalar b2r2a1 = msk.b_2.mul(r_2);
        sk.sk_0[1] = mpk.h.pow(b2r2a1);
        Scalar b2r2a2 = b2r2a1.div(msk.a_2);
        b2r2a1 = b2r2a1.div(msk.a_1);
        sk.sk_0[2] = mpk.h.pow(r_1.add(r_2));

        int i = 0;
        for(String y : S.attrs) {
            sk.Attr2id.put(y, i);
            Scalar sigma_y = pp.curve.getRandomScalar();
            sk.sk_y[i][0] = pp.H(y + "11").pow(b1r1a1)
                    .mul(pp.H(y + "21").pow(b2r2a1))
                    .mul(pp.H(y + "31").pow(r_1.add(r_2).div(msk.a_1))).mul(mpk.g.pow(sigma_y.div(msk.a_1)));

            sk.sk_y[i][1] = pp.H(y + "12").pow(b1r1a2)
                    .mul(pp.H(y + "22").pow(b2r2a2))
                    .mul(pp.H(y + "32").pow(r_1.add(r_2).div(msk.a_2))).mul(mpk.g.pow(sigma_y.div(msk.a_2)));
            sk.sk_y[i][2] = mpk.g.pow(sigma_y).inv();
            ++i;
        }

        Scalar sigma_p = pp.curve.getRandomScalar();

        sk.sk_p[0] = msk.g_d1.mul(pp.H("0111").pow(b1r1a1))
                .mul(pp.H("0121").pow(b2r2a1))
                .mul(pp.H("0131").pow(r_1.add(r_2).div(msk.a_1))).mul(mpk.g.pow(sigma_p.div(msk.a_1)));

        sk.sk_p[1] = msk.g_d2.mul(pp.H("0112").pow(b1r1a2))
                .mul(pp.H("0122").pow(b2r2a2))
                .mul(pp.H("0132").pow(r_1.add(r_2).div(msk.a_2))).mul(mpk.g.pow(sigma_p.div(msk.a_2)));

        sk.sk_p[2] = msk.g_d3.div(mpk.g.pow(sigma_p));
    }

    public void KeyGen(SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, Attributes S, Scalar r_1, Scalar r_2, Scalar alpha) {
        sk.Attr2id = new HashMap<>();
        sk.S.attrs.addAll(S.attrs);
        sk.sk_y = new MultivePoint[S.attrs.size()][3];

        Scalar b1r1a1 = msk.b_1.mul(r_1);
        sk.sk_0[0] = mpk.h.pow(b1r1a1);
        Scalar b1r1a2 = b1r1a1.div(msk.a_2);
        b1r1a1 = b1r1a1.div(msk.a_1);
        Scalar b2r2a1 = msk.b_2.mul(r_2);
        sk.sk_0[1] = mpk.h.pow(b2r2a1);
        Scalar b2r2a2 = b2r2a1.div(msk.a_2);
        b2r2a1 = b2r2a1.div(msk.a_1);
        sk.sk_0[2] = mpk.h.pow(r_1.add(r_2).div(alpha));

        Scalar alpha_a_1 = alpha.mul(msk.a_1);
        Scalar alpha_a_2 = alpha.mul(msk.a_2);

        int i = 0;
        for(String y : S.attrs) {
            sk.Attr2id.put(y, i);
            Scalar sigma_y = pp.curve.getRandomScalar();
            sk.sk_y[i][0] = pp.H(y + "11").pow(b1r1a1)
                    .mul(pp.H(y + "21").pow(b2r2a1))
                    .mul(pp.H(y + "31").pow(r_1.add(r_2).div(alpha_a_1))).mul(mpk.g.pow(sigma_y.div(alpha_a_1)));

            sk.sk_y[i][1] = pp.H(y + "12").pow(b1r1a2)
                    .mul(pp.H(y + "22").pow(b2r2a2))
                    .mul(pp.H(y + "32").pow(r_1.add(r_2).div(alpha_a_2))).mul(mpk.g.pow(sigma_y.div(alpha_a_2)));
            sk.sk_y[i][2] = mpk.g.pow(sigma_y).inv();
            ++i;
        }

        Scalar sigma_p = pp.curve.getRandomScalar();

        sk.sk_p[0] = msk.g_d1.mul(pp.H("0111").pow(b1r1a1))
                .mul(pp.H("0121").pow(b2r2a1))
                .mul(pp.H("0131").pow(r_1.add(r_2).div(alpha_a_1))).mul(mpk.g.pow(sigma_p.div(alpha_a_1)));

        sk.sk_p[1] = msk.g_d2.mul(pp.H("0112").pow(b1r1a2))
                .mul(pp.H("0122").pow(b2r2a2))
                .mul(pp.H("0132").pow(r_1.add(r_2).div(alpha_a_2))).mul(mpk.g.pow(sigma_p.div(alpha_a_2)));

        sk.sk_p[2] = msk.g_d3.div(mpk.g.pow(sigma_p));
    }

    public void Encrypt(CipherText ct, PublicParam pp, MasterPublicKey mpk, Policy P, PlainText pt, Scalar s_1, Scalar s_2) {
        ct.ct_0[0] = mpk.H_1.pow(s_1);
        ct.ct_0[1] = mpk.H_2.pow(s_2);
        ct.ct_0[2] = mpk.h.pow(s_1.add(s_2));

        ct.ct_p = mpk.T_1.pow(s_1).mul(mpk.T_2.pow(s_2)).mul(pt.m);
        
        int n1 = P.MSP.M.length, n2 = P.MSP.M[0].length;
        ct.ct = new MultivePoint[n1][3];

        MultivePoint[][] Hjl = new MultivePoint[n2][3];
        for(int l = 1;l <= 3;++l) {
            for (int j = 1; j <= n2; ++j) Hjl[j - 1][l - 1] = pp.H(String.format("0%d%d1", j, l)).pow(s_1).mul(pp.H(String.format("0%d%d2", j, l)).pow(s_2));
        }

        for(int i = 0; i < n1; ++i) {
            for(int l = 1;l <= 3;++l) {
                ct.ct[i][l - 1] = pp.H(String.format("%s%d1", P.MSP.policy[i], l)).pow(s_1).mul(pp.H(String.format("%s%d2", P.MSP.policy[i], l)).pow(s_2));
                for(int j = 1; j <= n2; ++j) ct.ct[i][l - 1] = ct.ct[i][l - 1].mul(Hjl[j - 1][l - 1].pow(P.MSP.M[i][j - 1]));
            }
        }
    }

    public void Decrypt(PlainText pt, PublicParam pp, MasterPublicKey mpk, SecretKey sk, CipherText ct, Policy P) {
        Scalar[] gamma = P.MSP.Solve(pp.curve, sk.S);
        MultivePoint num = ct.ct_p, tmp = pp.curve.createPoint(CurveGroup.G1);
        for(int t = 0;t < 3;++t) {
            boolean fir = true;
            for(int i = 0;i < ct.ct.length;++i) {
                if (fir) {
                    fir = false;
                    tmp = ct.ct[i][t].pow(gamma[i]);
                } else tmp = tmp.mul(ct.ct[i][t].pow(gamma[i]));
            }
            num = num.mul(pp.curve.Pairing(tmp, sk.sk_0[t]));
        }
        MultivePoint den = pp.curve.createPoint(CurveGroup.GT);
        for(int t = 0;t < 3;++t) {
            tmp = sk.sk_p[t];
            for(int i = 0;i < ct.ct.length;++i) {
                if(sk.Attr2id.get(P.MSP.policy[i]) == null) continue;
                tmp = tmp.mul(sk.sk_y[sk.Attr2id.get(P.MSP.policy[i])][t].pow(gamma[i]));
            }
            if(t == 0) den = pp.curve.Pairing(tmp, ct.ct_0[t]);
            else den = den.mul(pp.curve.Pairing(tmp, ct.ct_0[t]));
        }
        pt.m = num.div(den);
    }
}
