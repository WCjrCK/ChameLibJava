package Commitment;

public class NIZKFactory {
    private NIZKFactory() {}

    public static NIZK createScheme(NIZKConfig config) {
        try{
            NIZK res = (NIZK) config.scheme.schemeClass.getDeclaredConstructor().newInstance();
            res.curve = config.curve;
            return res;
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.scheme.name());
        }
    }
}
