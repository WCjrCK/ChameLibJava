package Encryption.ABE.RevocableABE.TMM_2022;

import Encryption.ABE.ABE;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.Interface.RevocableABE;
import Encryption.ABE.RevocableABE.Components.Attributes;

/*
 * Revocable Policy-Based ChameleonHash for Blockchain Rewriting
 * P7. 4.1. The proposed RABE scheme
 */

public class Scheme extends ABE
        implements RevocableABE<PublicParam, MasterPublicKey, MasterSecretKey,
        State, Revocated, Identity, UpdateKey, Info, SecretKey, DecryptKey, Policy, PlainText, CipherText>  {
    Core core = new Core();
    @Override
    public void Setup(MasterPublicKey mpk, MasterSecretKey msk, State st, Revocated rl, UpdateKey uk, PublicParam pp) {
        core.Setup(mpk, msk, pp);
    }

    @Override
    public void KeyGen(SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Revocated rl, Identity id, UpdateKey uk, DecryptKey dk, Attributes S) {
        core.KeyGen(sk, pp, mpk, msk, st, id, S);
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
    public void Revoke(Revocated rl, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Identity id, Info info) {
        core.Revoke(rl, id, info);
    }

    @Override
    public PublicParam createPublicParam(ABEConfig abeConfig) {
        return new PublicParam(abeConfig);
    }
}
