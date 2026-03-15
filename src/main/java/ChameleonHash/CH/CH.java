package ChameleonHash.CH;

import ChameleonHash.CH.CHET.Comoponents.ETrapdoor;
import ChameleonHash.CH.Components.*;
import ChameleonHash.CH.LabelCH.Components.Label;

public abstract class CH<
        PP extends PublicParam<PK, SK, M, H, R>,
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        L extends Label,
        ET extends ETrapdoor,
        H extends HashValue<H>,
        R extends Randomness
        > {
    public abstract PP createPublicParam(CHConfig config);

    public abstract void Setup(PP pp);

    public abstract void KeyGen(PK pk, SK sk, PP pp);

    public abstract void Hash(H h, R r, PP pp, PK pk, M m);

    public abstract void Hash(H h, R r, PP pp, PK pk, M m, ET etd);

    public abstract void Hash(H h, R r, PP pp, PK pk, M m, L l);

    public abstract boolean Verify(PP pp, PK pk, M m, H h, R r);

    public abstract boolean Verify(PP pp, PK pk, M m, L l, H h, R r);

    public abstract void Collision(R r_p, PP pp, PK pk, SK sk, M m, H h, R r, M m_p);

    public abstract void Collision(R r_p, PP pp, PK pk, SK sk, M m, ET etd, H h, R r, M m_p);

    public abstract void Collision(R r_p, PP pp, PK pk, SK sk, M m, L l, H h, R r, M m_p);
}
