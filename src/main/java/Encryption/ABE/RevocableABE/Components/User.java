package Encryption.ABE.RevocableABE.Components;

import utils.ElementCounter;

public abstract class User<
        PP extends PublicParam,
        MPK extends MasterPublicKey,
        SK extends SecretKey,
        I extends Info,
        ID extends Identity,
        P extends Policy,
        PT extends PlainText<PT>,
        CT extends CipherText<CT, P>
        > {
    public SK sk;
    public Attributes S;
    public final ID id;

    protected User(ID id) {
        this.id = id;
    }

    public abstract void Encrypt(CT ct, PP pp, MPK mpk, P P, PT pt, I info);

    public abstract void Decrypt(PT pt, PP pp, MPK mpk, P P, CT ct);

    public abstract ElementCounter TheoSize();
}
