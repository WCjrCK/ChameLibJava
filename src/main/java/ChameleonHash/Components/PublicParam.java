package ChameleonHash.Components;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import utils.ElementCounter;

public abstract class PublicParam<
        MSK extends MasterSecretKey,
        PK extends PublicKey,
        SK extends SecretKey,
        ID extends Identity,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > {
    public final Curve curve;

    protected PublicParam(Config config) {
        curve = CurveFactory.create(config);
    }

    public abstract M createMessage(String msg);

    public abstract ID createIdentity(String ID);

    public abstract MSK createMasterSecretKey();

    public abstract PK createPublicKey();

    public abstract SK createSecretKey();

    public abstract H createHashValue();

    public abstract R createRandomness();

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
