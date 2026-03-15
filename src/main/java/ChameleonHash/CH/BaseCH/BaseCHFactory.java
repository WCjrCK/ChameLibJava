package ChameleonHash.CH.BaseCH;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.BaseCH;

public class BaseCHFactory {
    private BaseCHFactory() {}

    public static BaseCH createScheme(CHConfig config) {
        try {
            assert (!config.schemeName.has_label);
            return (BaseCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
