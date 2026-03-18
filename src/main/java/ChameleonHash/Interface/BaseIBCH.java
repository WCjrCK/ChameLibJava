package ChameleonHash.Interface;

import ChameleonHash.IBCH.BaseIBCH.Components.*;
import ChameleonHash.IBCH.IBCHConfig;

public interface BaseIBCH<
        PP extends PublicParam<MSK, SK, M, ID, H, R>,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        ID extends Identity,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > {
    PP createPublicParam(IBCHConfig config);

    void Setup(PP pp, MSK msk);

    void KeyGen(SK sk, PP pp, MSK msk, ID ID);

    void Hash(H h, R r, PP pp, ID ID, M m);

    boolean Verify(PP pp, ID ID, M m, H h, R r);

    void Collision(R r_p, PP pp, ID ID, SK sk, M m, H h, R r, M m_p);
}
