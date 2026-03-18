package ChameleonHash.IBCH.LabelIBCH.Components;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import utils.ElementCounter;

public abstract class PublicParam<
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        M extends Message,
        I extends Identity,
        L extends ChameleonHash.IBCH.LabelIBCH.Components.Label,
        H extends HashValue<H>,
        R extends Randomness
        > {
    public final Curve curve;

    protected PublicParam(Config config) {
        curve = CurveFactory.create(config);
    }

    public abstract MSK createMasterSecretKey();

    public abstract SK createSecretKey();

    public abstract M createMessage(String msg);

    public abstract L createLabel(String L);

    public abstract I createIdentity(String ID);

    public abstract H createHashValue();

    public abstract R createRandomness();

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
