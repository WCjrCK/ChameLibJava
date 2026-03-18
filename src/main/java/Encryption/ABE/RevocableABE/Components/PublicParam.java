package Encryption.ABE.RevocableABE.Components;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import Encryption.ABE.ABEConfig;
import utils.ElementCounter;

public abstract class PublicParam<
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        S extends State,
        R extends Revocated,
        A extends Authority,
        U extends User,
        I extends Info,
        KU extends UpdateKey<I>,
        SK extends SecretKey,
        DK extends DecryptKey<I>,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > {
    public final Curve curve;

    protected PublicParam(ABEConfig abeConfig) {
        curve = CurveFactory.create(abeConfig.curveConfig);
    }

    public Attributes createAttributes() {
        return new Attributes();
    }

    public abstract Policy createPolicy(String BooleanFormulas);

    public abstract MPK createMasterPublicKey();

    public abstract MSK createMasterSecretKey();

    public abstract S createState();

    public abstract R createRevocated();

    public abstract U createUser(String ID);

    public abstract SK createSecretKey();

    public abstract A createAuthority();

    public abstract I createInfo();

    public abstract KU createKeyUpdater();

    public abstract DK createDecryptKey();

    public abstract PT createPlainText(String msg);

    public abstract CT createCipherText();

    public abstract ElementCounter TheoSize();
}
