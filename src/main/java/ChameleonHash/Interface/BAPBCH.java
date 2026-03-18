package ChameleonHash.Interface;

import ChameleonHash.PBCH.BAPBCH.Components.PublicParam;
import ChameleonHash.PBCH.BAPBCH.Components.User;
import ChameleonHash.PBCH.BasePBCH.Components.*;
import ChameleonHash.PBCH.PBCHConfig;

public interface BAPBCH<
        PP extends PublicParam,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        P extends Policy,
        U extends User,
        M extends Message,
        H extends HashValue,
        R extends Randomness
        > {
    PP createPublicParam(PBCHConfig config);

    void Setup(PP pp, MPK mpk, MSK msk);

    void AssignUser(U user, MPK mpk, MSK msk);

    void KeyGen(U user, PP pp, MPK mpk, MSK msk);

    void Hash(H h, R r, PP pp, MPK mpk, U user, M m, P P);

    boolean Verify(PP pp, MPK mpk, M m, H h, R r);

    void Collision(R r_p, PP pp, MPK mpk, MSK msk, U user, M m, P P, H h, R r, M m_p);
}
