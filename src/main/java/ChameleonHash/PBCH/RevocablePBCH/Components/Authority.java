package ChameleonHash.PBCH.RevocablePBCH.Components;

import Encryption.ABE.BaseABE.Components.MasterPublicKey;
import Encryption.ABE.BaseABE.Components.MasterSecretKey;
import Encryption.ABE.RevocableABE.Components.Info;
import Encryption.ABE.RevocableABE.Components.PublicParam;
import Encryption.ABE.RevocableABE.Components.Revocated;
import Encryption.ABE.RevocableABE.Components.State;
import Encryption.ABE.RevocableABE.Components.UpdateKey;
import Encryption.ABE.RevocableABE.Components.User;
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
