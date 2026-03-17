package Encryption.ABE.RevocableABE.Components;

import Encryption.ABE.Components.MasterPublicKey;
import Encryption.ABE.Components.MasterSecretKey;
import utils.ElementCounter;

public abstract class Authority<
        PP extends PublicParam,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        S extends State,
        R extends Revocated,
        UK extends UpdateKey,
        I extends Info,
        U extends User
        > {
    public MSK msk;
    public S st;
    public R rl;
    public UK uk;

    public abstract void Setup(MPK mpk, PP pp);

    public abstract void KeyGen(U user, PP pp, MPK mpk);

    public abstract void KeyUpdate(PP pp, MPK mpk, I info);

    public abstract void DecryptKeyGen(U user, PP pp, MPK mpk);

    public abstract void Revoke(PP pp, MPK mpk, U user, I info);

    public abstract ElementCounter TheoSize();
}
