package Encryption.ABE.RevocableABE.XNM_2021;

import Encryption.ABE.ABEConfig;
import Encryption.ABE.Components.Attributes;
import Encryption.ABE.Interface.RevocableABE;

public class Scheme
        extends Encryption.ABE.RevocableABE.Scheme<PublicParam, MasterPublicKey, MasterSecretKey,
        State, Revocated, User, UpdateKey, Info, SecretKey, DecryptKey, Policy, PlainText, CipherText>
        implements RevocableABE<PublicParam, MasterPublicKey, MasterSecretKey,
        State, Revocated, User, UpdateKey, Info, SecretKey, DecryptKey, Policy, PlainText, CipherText>  {
    Core core = new Core();
    @Override
    public void Setup(MasterPublicKey mpk, MasterSecretKey msk, State st, Revocated rl, UpdateKey uk, PublicParam pp) {
        core.Setup(mpk, msk, pp);
    }

    @Override
    public void KeyGen(SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Revocated rl, User user, UpdateKey uk, DecryptKey dk, Attributes S) {
        core.KeyGen(user, pp, mpk, msk, st);
    }

    @Override
    public void KeyUpdate(UpdateKey uk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Revocated rl, Info info) {
        core.KeyUpdate(uk, pp, mpk, st, rl, info);
    }

    @Override
    public void DecryptKeyGen(DecryptKey dk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Revocated rl, UpdateKey uk, SecretKey sk, Attributes S) {
        core.DecryptKeyGen(dk, pp, mpk, msk, st, rl, uk, sk);
    }

    @Override
    public void Encrypt(CipherText ct, PublicParam pp, MasterPublicKey mpk, Policy P, PlainText pt, Info info) {
        core.Encrypt(ct, pp, mpk, P, pt, info);
    }

    @Override
    public void Decrypt(PlainText pt, PublicParam pp, MasterPublicKey mpk, DecryptKey dk, SecretKey sk, Attributes S, CipherText ct, Policy P) {
        core.Decrypt(pt, pp, dk, ct, P);
    }

    @Override
    public void Revoke(Revocated rl, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, User user, Info info) {
        core.Revoke(rl, user, info);
    }

    @Override
    public PublicParam createPublicParam(ABEConfig abeConfig) {
        return new PublicParam(abeConfig);
    }
}
