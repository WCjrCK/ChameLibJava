package ChameleonHash.PBCH.MAPBCH.Components;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import utils.ElementCounter;

public abstract class PublicParam<
        PK extends PublicKey,
        SK extends SecretKey,
        Auth extends Authority,
        U extends User,
        ID extends Identity,
        A extends Attribute,
        P extends Policy,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > {
    public final Curve curve;

    protected PublicParam(Config config) {
        curve = CurveFactory.create(config);
    }

    public abstract M createMessage(String msg);

    public abstract Auth createAuthority();

    public abstract U createUser(String ID);

    public abstract ID createIdentity(String ID);

    public abstract PK createPublicKey();

    public abstract SK createSecretKey();

    public abstract P createPolicy(String BooleanFormula);

    public abstract A createAttribute(String attr);

    public abstract H createHashValue();

    public abstract R createRandomness();

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
