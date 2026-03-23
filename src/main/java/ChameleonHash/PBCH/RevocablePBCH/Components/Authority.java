package ChameleonHash.PBCH.RevocablePBCH.Components;

import utils.ElementCounter;

public abstract class Authority<
        PP extends PublicParam,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        S extends State,
        I extends Info,
        U extends User
        > {
    public MSK msk;
    public S st;

    public abstract void Setup(MPK mpk, PP pp);

    public abstract void KeyGen(U user, PP pp, MPK mpk);

    public abstract void KeyUpdate(PP pp, MPK mpk, I info);

    public abstract void DecryptKeyGen(U user, PP pp, MPK mpk);

    public abstract void Revoke(PP pp, MPK mpk, U user, I info);

    public abstract ElementCounter TheoSize();
}
