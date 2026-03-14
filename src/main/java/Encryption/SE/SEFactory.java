package Encryption.SE;

public class SEFactory {
    private SEFactory() {}
    public static SE createSE(Config config) {
        switch (config.seName) {
            case AES: return new Encryption.SE.AES.Scheme();
            default: throw new IllegalArgumentException("尚未支持当前方案：" + config.seName.name());
        }
    }

}
