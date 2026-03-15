package ChameleonHash.CH.Components;

import EllipticCurve.Curve.Config;
import utils.ElementCounter;

public abstract class PublicParam<
        PK extends PublicKey,
        SK extends SecretKey,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > extends ChameleonHash.Components.PublicParam<SK, M, H, R> {
    protected PublicParam(Config config) {
        super(config);
    }

    public abstract M createMessage(String msg);

    public abstract PK createPublicKey();

    public abstract SK createSecretKey();

    public abstract H createHashValue();

    public abstract R createRandomness();

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
