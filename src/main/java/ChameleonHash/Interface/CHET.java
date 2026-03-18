package ChameleonHash.Interface;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHET.Components.*;

public interface CHET<
        PP extends PublicParam<PK, SK, M, ET, H, R>,
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        ET extends ETrapdoor,
        H extends HashValue<H>,
        R extends Randomness
        > {
    PP createPublicParam(CHConfig config);

    void Setup(PP pp);

    void KeyGen(PK pk, SK sk, PP pp);

    void Hash(H h, R r, PP pp, PK pk, M m, ET etd);

    boolean Verify(PP pp, PK pk, M m, H h, R r);

    void Collision(R r_p, PP pp, PK pk, SK sk, M m, ET etd, H h, R r, M m_p);
}
