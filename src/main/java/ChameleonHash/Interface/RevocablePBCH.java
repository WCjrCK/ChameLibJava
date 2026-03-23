package ChameleonHash.Interface;

import ChameleonHash.PBCH.PBCHConfig;
import ChameleonHash.PBCH.RevocablePBCH.Components.*;

public interface RevocablePBCH<
        PP extends PublicParam,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        S extends State,
        SK extends SecretKey,
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

    void KeyGen(SK sk, PP pp, MPK mpk, MSK msk, S st, ID id, A S);

    void KeyUpdate(S st, PP pp, MPK mpk, MSK msk, I info);

    void DecryptKeyGen(SK sk, PP pp, MPK mpk, MSK msk, S st);

    void Revoke(S st, PP pp, MPK mpk, MSK msk, ID id, I info);

    void Hash(H h, R r, PP pp, MPK mpk, ID id, M m, P P, I info);

    boolean Verify(PP pp, MPK mpk, M m, H h, R r);

    void Collision(R r_p, PP pp, MPK mpk, SK sk, M m, H h, R r, M m_p);
}
