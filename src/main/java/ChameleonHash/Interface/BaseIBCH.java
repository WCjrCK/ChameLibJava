package ChameleonHash.Interface;

import ChameleonHash.Config;
import ChameleonHash.IBCH.Components.*;

public interface BaseIBCH<
        PP extends ChameleonHash.IBCH.Components.PublicParam<MSK, SK, ID, M, H, R>,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        ID extends Identity,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > {
    PP createPublicParam(Config config);

    void Setup(PP pp, MSK msk);

    void KeyGen(SK sk, PP pp, MSK msk, ID ID);

    void Hash(H h, R r, PP pp, ID ID, M m);

    boolean Verify(PP pp, ID ID, M m, H h, R r);

    void Collision(R r_p, PP pp, ID ID, SK sk, M m, H h, R r, M m_p);
}
