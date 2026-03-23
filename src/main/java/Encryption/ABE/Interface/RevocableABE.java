package Encryption.ABE.Interface;

import Encryption.ABE.ABEConfig;
import Encryption.ABE.RevocableABE.Components.*;

public interface RevocableABE<
        PP extends PublicParam,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        S extends State,
        ID extends Identity,
        I extends Info,
        SK extends SecretKey,
        P extends Policy,
        PT extends PlainText<PT>,
        CT extends CipherText<CT, P>
        > {
    void Setup(MPK mpk, MSK msk, S st, PP pp);

    void KeyGen(SK sk, PP pp, MPK mpk, MSK msk, S st, ID id, Attributes S);

    void KeyUpdate(S st, PP pp, MPK mpk, MSK msk, I info);

    void DecryptKeyGen(SK sk, PP pp, MPK mpk, MSK msk, S st);

    void Encrypt(CT ct, PP pp, MPK mpk, P P, PT pt, I info);

    void Decrypt(PT pt, PP pp, MPK mpk, SK sk, CT ct);

    void Revoke(S st, PP pp, MPK mpk, MSK msk, ID id, I info);

    PP createPublicParam(ABEConfig abeConfig);
}
