package ChameleonHash.CH.BaseCH;

import ChameleonHash.CH.CH;
import ChameleonHash.CH.CHConfig;
import ChameleonHash.CH.Components.*;
import ChameleonHash.Interface.BaseCH;

public abstract class Scheme<
        PP extends ChameleonHash.CH.Components.PublicParam<PK, SK, M, H, R>,
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > extends CH implements BaseCH<PP, PK, SK, M, H, R> {
    public abstract PP createPublicParam(CHConfig config);

    public abstract void Setup(PP pp);

    public abstract void KeyGen(PK pk, SK sk, PP pp);

    public abstract void Hash(H h, R r, PP pp, PK pk, M m);

    public abstract boolean Verify(PP pp, PK pk, M m, H h, R r);

    public abstract void Collision(R r_p, PP pp, PK pk, SK sk, M m, H h, R r, M m_p);
}
