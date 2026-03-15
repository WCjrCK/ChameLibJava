package ChameleonHash.IBCH.LabelIBCH.Components;

import ChameleonHash.IBCH.Components.*;
import EllipticCurve.Curve.Config;

public abstract class PublicParam<
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        ID extends Identity,
        M extends Message,
        L extends ChameleonHash.IBCH.LabelIBCH.Components.Label,
        H extends HashValue<H>,
        R extends Randomness
        > extends ChameleonHash.IBCH.Components.PublicParam<MSK, SK, ID, M, H, R> {
    protected PublicParam(Config config) {
        super(config);
    }

    public abstract L createLabel(String L);
}
