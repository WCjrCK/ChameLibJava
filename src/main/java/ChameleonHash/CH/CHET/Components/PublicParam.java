package ChameleonHash.CH.CHET.Components;

import ChameleonHash.CH.Components.*;
import EllipticCurve.Curve.Config;

public abstract class PublicParam<
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        E extends ETrapdoor,
        H extends HashValue<H>,
        R extends Randomness
        > extends ChameleonHash.CH.Components.PublicParam<PK, SK, M, H, R> {
    protected PublicParam(Config config) {
        super(config);
    }

    public abstract E createETrapdoor();
}
