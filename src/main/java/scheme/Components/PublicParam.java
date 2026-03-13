package scheme.Components;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import utils.ElementCounter;

public abstract class PublicParam {
    public Curve curve;

    protected PublicParam(Config config) {
        curve = CurveFactory.create(config);
    }

    public abstract Message createMessage(String msg);

    public abstract Identity createIdentity(String ID);

    public abstract MasterSecretKey createMasterSecretKey();

    public abstract SecretKey createSecretKey();

    public abstract HashValue createHashValue();

    public abstract Randomness createRandomness();

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
