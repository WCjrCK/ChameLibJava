package Encryption.ABE.Interface;

import Encryption.ABE.ABEConfig;
import Encryption.ABE.Components.*;
import Encryption.ABE.RevocableABE.Components.*;
import Encryption.ABE.RevocableABE.Components.PublicParam;

public interface RevocableABE<
        PP extends PublicParam,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        S extends State,
        R extends Revocated,
        U extends User,
        UK extends UpdateKey<I>,
        I extends Info,
        SK extends SecretKey,
        DK extends DecryptKey<I>,
        P extends Policy,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > {
    void Setup(MPK mpk, MSK msk, S st, R rl, UK uk, PP pp);

    void KeyGen(SK sk, PP pp, MPK mpk, MSK msk, S st, R rl, U user, UK uk, DK dk, Attributes S);

    void KeyUpdate(UK uk, PP pp, MPK mpk, MSK msk, S st, R rl, I info);

    void DecryptKeyGen(DK dk, PP pp, MPK mpk, MSK msk, S st, R rl, UK uk, SK sk, Attributes S);

    void Encrypt(CT ct, PP pp, MPK mpk, P P, PT pt, I info);

    void Decrypt(PT pt, PP pp, MPK mpk, DK dk, SK sk, Attributes S, CT ct, P P);

    void Revoke(R rl, PP pp, MPK mpk, MSK msk, S st, U user, I info);

    PP createPublicParam(ABEConfig abeConfig);
}
