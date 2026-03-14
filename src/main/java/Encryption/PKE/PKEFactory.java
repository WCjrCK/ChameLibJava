package Encryption.PKE;

public class PKEFactory {
    private PKEFactory() {}
    public static PKE createAE(Config config) {
        switch (config.PKEName) {
            case RSA: return new Encryption.PKE.RSA.Scheme();
            default: throw new IllegalArgumentException("尚未支持当前方案：" + config.PKEName.name());
        }
    }

}
