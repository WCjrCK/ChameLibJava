package Encryption.ABE.RevocableABE.Components;

import Encryption.ABE.Components.*;
import utils.ElementCounter;

public abstract class User<
        PP extends PublicParam,
        MPK extends MasterPublicKey,
        SK extends SecretKey,
        DK extends DecryptKey,
        I extends Info,
        P extends Policy,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > {
    public SK sk;
    public DK dk;
    public Attributes S;

    public abstract void Encrypt(CT ct, PP pp, MPK mpk, P P, PT pt, I info);

    public abstract void Decrypt(PT pt, PP pp, MPK mpk, P P, CT ct);

    public abstract ElementCounter TheoSize();
}
