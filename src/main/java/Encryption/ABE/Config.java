package Encryption.ABE;

public class Config {
    public EllipticCurve.Curve.Config curveConfig;

    Config(EllipticCurve.Curve.Config curveConfig) {
        this.curveConfig = curveConfig;
    }
}
