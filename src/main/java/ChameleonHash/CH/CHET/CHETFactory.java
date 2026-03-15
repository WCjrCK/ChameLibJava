package ChameleonHash.CH.CHET;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.CHET;

public class CHETFactory {
    private CHETFactory() {}

    public static CHET createScheme(CHConfig config) {
        try {
            assert (config.schemeName.has_ET);
            return (CHET) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
