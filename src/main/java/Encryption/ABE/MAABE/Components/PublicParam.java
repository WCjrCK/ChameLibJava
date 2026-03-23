package Encryption.ABE.MAABE.Components;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import Encryption.ABE.ABEConfig;
import utils.ElementCounter;

public abstract class PublicParam<
        APK extends AuthPublicKey,
        ASK extends AuthSecretKey,
        AUTH extends Authority,
        U extends User,
        P extends Policy,
        ID extends Identity,
        A extends Attribute,
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

    public abstract A createAttribute(String attr);

    public abstract PK createPublicKey();

    public abstract PKG createPublicKeyGroup();

    public abstract SK createSecretKey();

    public abstract SKG createSecretKeyGroup();

    public abstract AUTH createAuthority();

    public abstract PT createPlainText(String msg);

    public abstract PT createPlainText(byte[] data);

    public abstract CT createCipherText();

    public abstract ElementCounter TheoSize();
}
