package Encryption.ABE;


import Encryption.ABE.Components.*;

public abstract class ABE<
        PP extends PublicParam<MPK, MSK, SK, PT, CT>,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > {
    public abstract void Setup(MPK mpk, MSK msk, PP pp);

    public abstract void KeyGen(SK sk, PP pp, MPK mpk, MSK msk, Attributes S);

    public abstract void Encrypt(CT ct, PP pp, MPK mpk, Policy MSP, PT pt);

    public abstract void Decrypt(PT pt, PP pp, MPK mpk, SK sk, CT ct, Policy MSP);

    public abstract PP createPublicParam(Config config);
}
