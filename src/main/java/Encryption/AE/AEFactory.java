package Encryption.AE;

public class AEFactory {
    private AEFactory() {}
    public static AE createAE(Config config) {
        switch (config.aeName) {
            case RSA: return new Encryption.AE.RSA.Scheme();
            default: throw new IllegalArgumentException("尚未支持当前方案：" + config.aeName.name());
        }
    }

}
