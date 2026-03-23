package Encryption.ABE.MAABE.RW_2015;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.BaseABE.Components.Attributes;

public class Core {
    public PublicParam createPublicParam(ABEConfig abeConfig) {
        return new PublicParam(abeConfig);
    }

    public void Setup(PublicParam pp) {
        pp.g = pp.curve.getRandomPoint(CurveGroup.G1);
        pp.egg = pp.curve.Pairing(pp.g, pp.g);
    }

    public void AuthSetup(Authority auth, PublicParam pp) {
        auth.ask.alpha = pp.curve.getRandomScalar();
        auth.ask.y = pp.curve.getRandomScalar();
        auth.apk.egg_alpha = pp.egg.pow(auth.ask.alpha);
        auth.apk.g_y = pp.g.pow(auth.ask.y);
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp, Authority auth, Identity id, Attribute attr) {
        if(auth.controled_attr.contains(attr)) {
            Scalar t = pp.curve.getRandomScalar();
            sk.K_p = pp.g.pow(t);
            sk.K = pp.g.pow(auth.ask.alpha).mul(pp.H(id.id).pow(auth.ask.y)).mul(pp.F(attr.attr).pow(t));
        }
        pk.egg_alpha = auth.apk.egg_alpha;
        pk.g_y = auth.apk.g_y;
//        SK.GID = GID;
//        SK.u = u;
    }

    public void Encrypt(CipherText ct, PublicParam pp, PublicKeyGroup pkg, Policy P, PlainText pt) {
        int l = P.MSP.M.length;
        int n = P.MSP.M[0].length;
        Scalar[] v = new Scalar[n];
        for(int i = 0;i < n;++i) v[i] = pp.curve.getRandomScalar();
        Scalar[] t_x = new Scalar[l];
        for(int i = 0;i < l;++i) t_x[i] = pp.curve.getRandomScalar();
        Scalar[] w = new Scalar[n];
        w[0] = pp.curve.getZeroScalar();
        for(int i = 1;i < n;++i) w[i] = pp.curve.getRandomScalar();
        Encrypt(ct, pp, pkg, P, pt, v, w, t_x);
    }

    public void Encrypt(CipherText ct, PublicParam pp, PublicKeyGroup pkg, Policy P, PlainText pt, Scalar[] v, Scalar[] w, Scalar[] t_x) {
        int l = P.MSP.M.length;

        ct.C = new MultivePoint[4][l];
        ct.C_0 = pt.m.mul(pp.egg.pow(v[0]));

        int rho_x;

        for(int i = 0;i < l;++i) {
            if(!pkg.rho.containsKey(new Attribute(P.MSP.policy[i]))) throw new RuntimeException("错误属性 " + P.MSP.policy[i]);
            ct.C[3][i] = pp.F(P.MSP.policy[i]).pow(t_x[i]);
            rho_x = pkg.rho.get(new Attribute(P.MSP.policy[i]));
            ct.C[0][i] = pkg.PKS.get(rho_x).egg_alpha.pow(t_x[i]).mul(pp.egg.pow(P.MSP.Prodith(v, i)));
            ct.C[1][i] = pp.g.pow(t_x[i]).inv();
            ct.C[2][i] = pkg.PKS.get(rho_x).g_y.pow(t_x[i]).mul(pp.g.pow(P.MSP.Prodith(w, i)));
        }
        ct.P = P;
    }

    public void Decrypt(PlainText pt, PublicParam pp, Identity id, SecretKeyGroup skg, CipherText ct) {
        Attributes S = new Attributes();
        for (Attribute attr : skg.rho.keySet()) S.attrs.add(attr.attr);
        Scalar[] c = ct.P.MSP.Solve(pp.curve, S);
        MultivePoint tmp = pp.curve.getOne(CurveGroup.GT);
        for(int i = 0;i < ct.P.MSP.policy.length;++i) {
            if(!c[i].isZero()) {
                int sk_id = skg.rho.get(new Attribute(ct.P.MSP.policy[i]));
                tmp = tmp.mul(
                        ct.C[0][i].mul(pp.curve.Pairing(skg.SKS.get(sk_id).K, ct.C[1][i]))
                                .mul(pp.curve.Pairing(pp.H(id.id), ct.C[2][i]))
                                .mul(pp.curve.Pairing(skg.SKS.get(sk_id).K_p, ct.C[3][i]))
                                .pow(c[i])
                );
            }
        }
        pt.m = ct.C_0.div(tmp);
    }
}
