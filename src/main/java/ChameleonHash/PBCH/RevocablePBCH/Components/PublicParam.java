package ChameleonHash.PBCH.RevocablePBCH.Components;

import EllipticCurve.Curve.Config;
import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import utils.ElementCounter;

public abstract class PublicParam<
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        S extends State,
        PK extends PublicKey,
        SK extends SecretKey,
        Auth extends Authority,
        U extends User,
        ID extends Identity,
        A extends Attributes,
        I extends Info,
        P extends Policy,
        M extends Message,
        H extends HashValue<H>,
        R extends Randomness
        > {
    public final Curve curve;

    protected PublicParam(Config config) {
        curve = CurveFactory.create(config);
    }

    public abstract MPK createMasterPublicKey();

    public abstract MSK createMasterSecretKey();

    public abstract S createState();

    public abstract I createInfo();

    public abstract M createMessage(String msg);

    public abstract Auth createAuthority();

    public abstract U createUser(String ID);

    public abstract ID createIdentity(String ID);

    public abstract PK createPublicKey();

    public abstract SK createSecretKey();

    public abstract P createPolicy(String BooleanFormula);

    public abstract A createAttributes();

    public abstract H createHashValue();

    public abstract R createRandomness();

    public abstract String toString();

    public abstract ElementCounter TheoSize();
}
