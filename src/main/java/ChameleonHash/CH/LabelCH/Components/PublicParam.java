package ChameleonHash.CH.LabelCH.Components;

import ChameleonHash.CH.Components.*;
import EllipticCurve.Curve.Config;

public abstract class PublicParam<
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        L extends ChameleonHash.CH.LabelCH.Components.Label,
        H extends HashValue<H>,
        R extends Randomness
        > extends ChameleonHash.CH.Components.PublicParam<PK, SK, M, H, R> {
    protected PublicParam(Config config) {
        super(config);
    }

    public abstract L createLabel(String L);
}
