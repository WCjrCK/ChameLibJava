package Encryption.ABE.MAABE.RW_2015;

import Encryption.ABE.ABEConfig;
import Encryption.ABE.Interface.MAABE;

public class Scheme implements MAABE<
        PublicParam, PublicKey, PublicKeyGroup, SecretKey,
        SecretKeyGroup, Authority, User, Identity, Attribute, Policy, PlainText, CipherText> {
    private final Core core = new Core();

    @Override
    public PublicParam createPublicParam(ABEConfig abeConfig) {
        return core.createPublicParam(abeConfig);
    }
    @Override
    public void Setup(PublicParam pp) {
        core.Setup(pp);
    }

    @Override
    public void AuthSetup(Authority auth, PublicParam pp) {
        core.AuthSetup(auth, pp);
    }

    @Override
    public void UserSetup(User user, PublicParam pp) {}

    @Override
    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp, Authority auth, Identity id, Attribute attr) {
        core.KeyGen(pk, sk, pp, auth, id, attr);
    }

    @Override
    public void Encrypt(CipherText ct, PublicParam pp, PublicKeyGroup pkg, Policy P, PlainText pt) {
        core.Encrypt(ct, pp, pkg, P, pt);
    }

    @Override
    public void Decrypt(PlainText pt, PublicParam pp, Identity id, SecretKeyGroup skg, CipherText ct) {
        core.Decrypt(pt, pp, id, skg, ct);
    }
}
