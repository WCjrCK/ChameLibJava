package Encryption.ABE.BaseABE.FAME;

import EllipticCurve.Point.Scalar;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.Components.Attributes;
import Encryption.ABE.Interface.BaseABE;

public class Scheme
        extends Encryption.ABE.BaseABE.Scheme<PublicParam, MasterPublicKey, MasterSecretKey, SecretKey, Policy, PlainText, CipherText>
        implements BaseABE<PublicParam, MasterPublicKey, MasterSecretKey, SecretKey, Policy, PlainText, CipherText> {
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
    public void Encrypt(CipherText ct, PublicParam pp, MasterPublicKey mpk, Policy P, PlainText pt) {
        Scalar s_1 = pp.curve.getRandomScalar();
        Scalar s_2 = pp.curve.getRandomScalar();
        Core.Encrypt(ct, pp, mpk, P, pt, s_1, s_2);
    }

    @Override
    public void Decrypt(PlainText pt, PublicParam pp, MasterPublicKey mpk, SecretKey sk, CipherText ct, Policy P) {
        Core.Decrypt(pt, pp, mpk, sk, ct, P);
    }

    @Override
    public PublicParam createPublicParam(ABEConfig abeConfig) {
        return Core.createPublicParam(abeConfig);
    }
}
