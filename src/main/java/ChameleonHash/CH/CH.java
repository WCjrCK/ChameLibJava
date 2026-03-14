package ChameleonHash.CH;

import EllipticCurve.Curve.CurveName;
import ChameleonHash.CH.Components.*;
import ChameleonHash.Components.Identity;
import ChameleonHash.Components.MasterSecretKey;
import ChameleonHash.Scheme;

import java.util.Map;

public abstract class CH<
        PP extends PublicParam<PK, SK, M, H, R>,
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        >
        extends Scheme<PP, MasterSecretKey, PK, SK, Identity, M, H, R> {
    public abstract PP createPublicParam(CurveName curveName, Map<String, Object> params);

    public abstract void Setup(PP pp);

    public abstract void KeyGen(PK pk, SK sk, PP pp);

    public abstract void Hash(H h, R r, PP pp, M m);

    public abstract boolean Verify(PP pp, M m, H h, R r);

    public abstract void Collision(R r_p, PP pp, SK sk, M m, H h, R r, M m_p);
}
