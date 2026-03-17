package Encryption.ABE.Interface;

import Encryption.ABE.ABEConfig;
import Encryption.ABE.Components.*;

public interface RevocableABE<
        PP extends PublicParam<MPK, MSK, SK, PT, CT>,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > {
    PP createPublicParam(ABEConfig abeConfig);

    void Setup(MPK mpk, MSK msk, PP pp);

    void KeyGen(SK sk, PP pp, MPK mpk, MSK msk, Attributes S);

    void Encrypt(CT ct, PP pp, MPK mpk, Policy MSP, PT pt);

    void Decrypt(PT pt, PP pp, MPK mpk, SK sk, CT ct, Policy MSP);
}
