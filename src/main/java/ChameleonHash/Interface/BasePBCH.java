package ChameleonHash.Interface;

import ChameleonHash.PBCH.BasePBCH.Components.*;
import ChameleonHash.PBCH.PBCHConfig;

public interface BasePBCH<
        PP extends PublicParam<MPK, MSK, SK, P, A, M, H, R>,
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        P extends Policy,
        A extends Attributes,
        M extends Message,
        H extends HashValue<H, P>,
        R extends Randomness
        > {
    PP createPublicParam(PBCHConfig config);

    void Setup(PP pp, MPK mpk, MSK msk);

    void KeyGen(SK sk, PP pp, MPK mpk, MSK msk, A S);

    void Hash(H h, R r, PP pp, MPK mpk, M m, P P);

    boolean Verify(PP pp, MPK mpk, M m, H h, R r);

    void Collision(R r_p, PP pp, MPK mpk, SK sk, M m, H h, R r, M m_p);
}
