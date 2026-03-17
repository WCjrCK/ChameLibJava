package Encryption.ABE.BaseABE;


import Encryption.ABE.ABE;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.Components.*;
import Encryption.ABE.Interface.BaseABE;

public abstract class Scheme<
        PP extends PublicParam<MPK, MSK, SK, PT, CT>,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        P extends Policy,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > extends ABE implements BaseABE<PP, MPK, MSK, SK, P, PT, CT> {
    public abstract void Setup(MPK mpk, MSK msk, PP pp);

    public abstract void KeyGen(SK sk, PP pp, MPK mpk, MSK msk, Attributes S);

    public abstract void Encrypt(CT ct, PP pp, MPK mpk, P P, PT pt);

    public abstract void Decrypt(PT pt, PP pp, MPK mpk, SK sk, CT ct, P P);

    public abstract PP createPublicParam(ABEConfig abeConfig);
}
