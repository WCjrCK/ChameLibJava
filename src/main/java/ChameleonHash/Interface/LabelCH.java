package ChameleonHash.Interface;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.LabelCH.Components.*;

public interface LabelCH<
        PP extends PublicParam<PK, SK, M, L, H, R>,
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        L extends Label,
        H extends HashValue<H>,
        R extends Randomness
        > {
    PP createPublicParam(CHConfig config);

    void Setup(PP pp);

    void KeyGen(PK pk, SK sk, PP pp);

    void Hash(H h, R r, PP pp, PK pk, M m, L l);

    boolean Verify(PP pp, PK pk, M m, L l, H h, R r);

    void Collision(R r_p, PP pp, PK pk, SK sk, M m, L l, H h, R r, M m_p);
}
