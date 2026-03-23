package Encryption.ABE.RevocableABE.XNM_2021;

import Encryption.ABE.ABE;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.Interface.RevocableABE;
import Encryption.ABE.RevocableABE.Components.Attributes;

/*
 * Revocable Policy-Based Chameleon Hash
 * P12. 5.1 Proposed RABE
 */

public class Scheme extends ABE
        implements RevocableABE<PublicParam, MasterPublicKey, MasterSecretKey,
        State, Identity, Info, SecretKey, Policy, PlainText, CipherText>  {
    Core core = new Core();
    @Override
    public void Setup(MasterPublicKey mpk, MasterSecretKey msk, State st, PublicParam pp) {
        core.Setup(mpk, msk, pp);
    }

    @Override
    public void KeyGen(SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st, Identity id, Attributes S) {
        core.KeyGen(sk, pp, mpk, msk, st, id, S);
    }

    @Override
    public void KeyUpdate(State st, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, Info info) {
        core.KeyUpdate(st, pp, mpk, info);
    }

    @Override
    public void DecryptKeyGen(SecretKey sk, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, State st) {
        core.DecryptKeyGen(sk, pp, mpk, msk, st);
    }

    @Override
    public void Encrypt(CipherText ct, PublicParam pp, MasterPublicKey mpk, Policy P, PlainText pt, Info info) {
        core.Encrypt(ct, pp, mpk, P, pt, info);
    }

    @Override
    public void Decrypt(PlainText pt, PublicParam pp, MasterPublicKey mpk, SecretKey sk, CipherText ct) {
        core.Decrypt(pt, pp, sk, ct);
    }

    @Override
    public void Revoke(State st, PublicParam pp, MasterPublicKey mpk, MasterSecretKey msk, Identity id, Info info) {
        core.Revoke(st, id, info);
    }

    @Override
    public PublicParam createPublicParam(ABEConfig abeConfig) {
        return new PublicParam(abeConfig);
    }
}
