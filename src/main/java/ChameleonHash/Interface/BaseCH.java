package ChameleonHash.Interface;

import ChameleonHash.CH.BaseCH.Components.*;
import ChameleonHash.CH.CHConfig;

public interface BaseCH<
        PP extends PublicParam<PK, SK, M, H, R>,
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > {
    PP createPublicParam(CHConfig config);

    void Setup(PP pp);

    void KeyGen(PK pk, SK sk, PP pp);

    void Hash(H h, R r, PP pp, PK pk, M m);

    boolean Verify(PP pp, PK pk, M m, H h, R r);

    void Collision(R r_p, PP pp, PK pk, SK sk, M m, H h, R r, M m_p);
}
