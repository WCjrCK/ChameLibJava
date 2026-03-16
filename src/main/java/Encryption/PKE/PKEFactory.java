package Encryption.PKE;

public class PKEFactory {
    private PKEFactory() {}
    public static PKE createPKE(PKEConfig pkeConfig) {
        switch (pkeConfig.PKEName) {
            case RSA: return new Encryption.PKE.RSA.Scheme();
            default: throw new IllegalArgumentException("尚未支持当前方案：" + pkeConfig.PKEName.name());
        }
    }

}
