package Encryption.ABE.FAME;

import EllipticCurve.Curve.CurveGroup;
import EllipticCurve.Point.MultivePoint;
import EllipticCurve.Point.Scalar;
import Encryption.ABE.ABE;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.Components.Attributes;
import Encryption.ABE.Components.Policy;

public class Scheme extends ABE<PublicParam, MasterPublicKey, MasterSecretKey, SecretKey, PlainText, CipherText> {
    private FAMECore Core = new FAMECore();

    @Override
    public void Setup(MasterPublicKey mpk, MasterSecretKey msk, PublicParam pp) {
        Scalar d_1 = pp.curve.getRandomScalar();
        Scalar d_2 = pp.curve.getRandomScalar();
        Scalar d_3 = pp.curve.getRandomScalar();
        Core.Setup(mpk, msk, pp, d_1, d_2, d_3, pp.curve.getOneScalar());
    }

    @Override
    public void KeyGen(SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, Attributes S) {
        Scalar r_1 = pp.curve.getRandomScalar();
        Scalar r_2 = pp.curve.getRandomScalar();
        Core.KeyGen(sk, pp, mpk, msk, S, r_1, r_2, pp.curve.getOneScalar());
    }

    @Override
    public void Encrypt(CipherText ct, PublicParam pp, MasterPublicKey mpk, Policy MSP, PlainText pt) {
        Scalar s_1 = pp.curve.getRandomScalar();
        Scalar s_2 = pp.curve.getRandomScalar();
        Core.Encrypt(ct, pp, mpk, MSP, pt, s_1, s_2);
    }

    @Override
    public void Decrypt(PlainText pt, PublicParam pp, MasterPublicKey mpk, SecretKey sk, CipherText ct, Policy MSP) {
        Policy.Vector gamma = new Policy.Vector();
        MSP.Solve(gamma, pp.curve, sk.S);
        MultivePoint num = ct.ct_p, tmp = pp.curve.createPoint(CurveGroup.G1);
        for(int t = 0;t < 3;++t) {
            boolean fir = true;
            for(int i = 0;i < ct.ct.length;++i) {
                if (fir) {
                    fir = false;
                    tmp = ct.ct[i][t].pow(gamma.v[i]);
                } else tmp = tmp.mul(ct.ct[i][t].pow(gamma.v[i]));
            }
            num = num.mul(pp.curve.Pairing(tmp, sk.sk_0[t]));
        }
        MultivePoint den = pp.curve.createPoint(CurveGroup.GT);
        for(int t = 0;t < 3;++t) {
            tmp = sk.sk_p[t];
            for(int i = 0;i < ct.ct.length;++i) {
                if(sk.Attr2id.get(MSP.policy[i]) == null) continue;
                tmp = tmp.mul(sk.sk_y[sk.Attr2id.get(MSP.policy[i])][t].pow(gamma.v[i]));
            }
            if(t == 0) den = pp.curve.Pairing(tmp, ct.ct_0[t]);
            else den = den.mul(pp.curve.Pairing(tmp, ct.ct_0[t]));
        }
        pt.m = num.div(den);
    }

    @Override
    public PublicParam createPublicParam(ABEConfig abeConfig) {
        return Core.createPublicParam(abeConfig);
    }
}
