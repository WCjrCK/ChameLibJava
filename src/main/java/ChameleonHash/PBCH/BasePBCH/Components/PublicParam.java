package ChameleonHash.PBCH.BasePBCH.Components;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import utils.ElementCounter;

public abstract class PublicParam<
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        P extends Policy,
        A extends Attributes,
        M extends Message,
        H extends HashValue<H, P>,
        R extends Randomness
        > {
    public final Curve curve;

    protected PublicParam(Config config) {
        curve = CurveFactory.create(config);
    }

    public abstract M createMessage(String msg);

    public abstract MPK createMasterPublicKey();

    public abstract MSK createMasterSecretKey();

    public abstract SK createSecretKey();

    public abstract P createPolicy(String BooleanFormula);

    public abstract A createAttributes();

    public abstract H createHashValue();

    public abstract R createRandomness();

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
