package ChameleonHash.Interface;

import ChameleonHash.PBCH.PBCHConfig;
import ChameleonHash.PBCH.RevocablePBCH.Components.*;

public interface RevocablePBCH<
        PP extends PublicParam,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        S extends State,
        RL extends Revocated,
        UK extends UpdateKey,
        PK extends PublicKey,
        SK extends SecretKey,
        DK extends DecryptKey,
        ID extends Identity,
        A extends Attributes,
        I extends Info,
        P extends Policy,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > {
    PP createPublicParam(PBCHConfig config);

    void Setup(PP pp, MPK mpk, MSK msk);

//    void AssignUser(U user, PP pp, MPK mpk, MSK msk);

    void KeyGen(SK sk, PP pp, MPK mpk, MSK msk, S st, RL rl, ID id, UK uk, DK dk, A S);

    void KeyUpdate(UK uk, PP pp, MPK mpk, MSK msk, S st, RL rl, I info);

    void DecryptKeyGen(DK dk, PP pp, MPK mpk, MSK msk, S st, RL rl, UK uk, SK sk, A S);

    void Revoke(RL rl, PP pp, MPK mpk, MSK msk, S st, ID id, I info);

    void Hash(H h, R r, PP pp, MPK mpk, ID id, PK pk, M m, P P, I info);

    boolean Verify(PP pp, MPK mpk, PK pk, M m, H h, R r);

    void Collision(R r_p, PP pp, MPK mpk, PK pk, SK sk, DK dk, M m, P P, H h, R r, M m_p);
}
