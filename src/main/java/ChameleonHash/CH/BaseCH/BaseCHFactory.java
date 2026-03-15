package ChameleonHash.CH.BaseCH;

import ChameleonHash.Config;
import ChameleonHash.Interface.BaseCH;
import ChameleonHash.SchemeType;

public class BaseCHFactory {
    private BaseCHFactory() {}

    public static BaseCH createScheme(Config config) {
        try {
            assert config.schemeName.schemeType == SchemeType.CH && (!config.schemeName.has_label);
            return (BaseCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
