package ChameleonHash.CH.CHET;

import ChameleonHash.CH.CH;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.CHET.Components.ETrapdoor;
import ChameleonHash.CH.CHET.Components.PublicParam;
import ChameleonHash.CH.Components.*;
import ChameleonHash.Interface.CHET;

public abstract class Scheme<
        PP extends PublicParam<PK, SK, M, ET, H, R>,
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        ET extends ETrapdoor,
        H extends HashValue<H>,
        R extends Randomness
        >  extends CH implements CHET<PP, PK, SK, M, ET, H, R> {
    public abstract PP createPublicParam(CHConfig config);

    public abstract void Setup(PP pp);

    public abstract void KeyGen(PK pk, SK sk, PP pp);

    public abstract void Hash(H h, R r, PP pp, PK pk, M m, ET etd);

    public abstract boolean Verify(PP pp, PK pk, M m, H h, R r);

    public abstract void Collision(R r_p, PP pp, PK pk, SK sk, M m, ET etd, H h, R r, M m_p);
}
