package Encryption.SE;

public class SEFactory {
    private SEFactory() {}
    public static SE createSE(SEConfig seConfig) {
        switch (seConfig.seName) {
            case AES: return new Encryption.SE.AES.Scheme();
            default: throw new IllegalArgumentException("尚未支持当前方案：" + seConfig.seName.name());
        }
    }

}
