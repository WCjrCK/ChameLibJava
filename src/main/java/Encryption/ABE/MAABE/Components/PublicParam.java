package Encryption.ABE.MAABE.Components;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import Encryption.ABE.ABEConfig;
import utils.ElementCounter;

public abstract class PublicParam<
        APK extends AuthPublicKey,
        ASK extends AuthSecretKey,
        A extends Authority,
        U extends User,
        P extends Policy,
        ID extends Identity,
        PKG extends PublicKeyGroup,
        SKG extends SecretKeyGroup,
        PK extends PublicKey,
        SK extends SecretKey,
        PT extends PlainText<PT>,
        CT extends CipherText<CT, P>
        > {
    public final Curve curve;

    protected PublicParam(ABEConfig abeConfig) {
        curve = CurveFactory.create(abeConfig.curveConfig);
    }

    public abstract P createPolicy(String BooleanFormulas);

    public abstract APK createAuthPublicKey();

    public abstract ASK createAuthSecretKey();

    public abstract U createUser(String ID);

    public abstract ID createIdentity(String ID);

    public abstract PK createPublicKey();

    public abstract PKG createPublicKeyGroup();

    public abstract SK createSecretKey();

    public abstract SKG createSecretKeyGroup();

    public abstract A createAuthority();

    public abstract PT createPlainText(String msg);

    public abstract CT createCipherText();

    public abstract ElementCounter TheoSize();
}
