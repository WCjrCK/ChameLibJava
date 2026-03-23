package Encryption.ABE.Interface;

import Encryption.ABE.ABEConfig;
import Encryption.ABE.BaseABE.Components.*;

public interface BaseABE<
        PP extends PublicParam<MPK, MSK, SK, PT, CT>,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        P extends Policy,
        PT extends PlainText<PT>,
        CT extends CipherText<CT, P>
        > {
    void Setup(MPK mpk, MSK msk, PP pp);

    void KeyGen(SK sk, PP pp, MPK mpk, MSK msk, Attributes S);

    void Encrypt(CT ct, PP pp, MPK mpk, P P, PT pt);

    void Decrypt(PT pt, PP pp, MPK mpk, SK sk, CT ct);

    PP createPublicParam(ABEConfig abeConfig);
}
