package ChameleonHash.CH.LabelCH.Components;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import utils.ElementCounter;

public abstract class PublicParam<
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        L extends Label,
        H extends HashValue<H>,
        R extends Randomness
        > {
    public final Curve curve;
    protected PublicParam(Config config) {
        curve = CurveFactory.create(config);
    }

    public abstract M createMessage(String msg);

    public abstract PK createPublicKey();

    public abstract SK createSecretKey();

    public abstract H createHashValue();

    public abstract R createRandomness();

    public abstract L createLabel(String L);

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
