package ChameleonHash.PBCH.BAPBCH;

import ChameleonHash.Interface.BAPBCH;
import ChameleonHash.PBCH.BAPBCH.Components.PublicParam;
import ChameleonHash.PBCH.BAPBCH.Components.User;
import ChameleonHash.PBCH.Components.*;
import ChameleonHash.PBCH.PBCH;
import ChameleonHash.PBCH.PBCHConfig;

public abstract class Scheme<
        PP extends PublicParam,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        P extends Policy,
        U extends User,
        M extends Message,
        H extends HashValue,
        R extends Randomness
        > extends PBCH implements BAPBCH<PP, MPK, MSK, P, U, M, H, R> {
    public abstract PP createPublicParam(PBCHConfig config);

    public abstract void Setup(PP pp, MPK mpk, MSK msk);

    public abstract void AssignUser(U user, MPK mpk, MSK msk);

    public abstract void KeyGen(U user, PP pp, MPK mpk, MSK msk);

    public abstract void Hash(H h, R r, PP pp, MPK mpk, U user, M m, P P);

    public abstract boolean Verify(PP pp, MPK mpk, M m, H h, R r);

    public abstract void Collision(R r_p, PP pp, MPK mpk, MSK msk, U user, M m, P P, H h, R r, M m_p);
}
