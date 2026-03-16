package Encryption.ABE.Components;

import EllipticCurve.Curve.Curve;
import EllipticCurve.Curve.CurveFactory;
import Encryption.ABE.ABEConfig;
import Encryption.ABE.utils.BooleanFormulaParser;
import utils.ElementCounter;

public abstract class PublicParam<
        MPK extends MasterPublicKey,
        MSK extends MasterSecretKey,
        SK extends SecretKey,
        PT extends PlainText<PT>,
        CT extends CipherText<CT>
        > {
    public final Curve curve;

    protected PublicParam(ABEConfig abeConfig) {
        curve = CurveFactory.create(abeConfig.curveConfig);
    }

    public abstract Attributes createAttributes();

    public final Policy createPolicy(String BooleanFormulas) {
        Policy res = new Policy();
        res.formula = BooleanFormulas;
        BooleanFormulaParser.parse(res, curve, BooleanFormulas);
        return res;
    }

    public abstract MPK createMasterPublicKey();

    public abstract MSK createMasterSecretKey();

    public abstract SK createSecretKey();

    public abstract PT createPlainText(String msg);

    public abstract CT createCipherText();

    public abstract ElementCounter TheoSize();
}
