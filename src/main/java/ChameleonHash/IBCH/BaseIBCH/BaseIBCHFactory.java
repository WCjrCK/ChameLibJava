package ChameleonHash.IBCH.BaseIBCH;

import ChameleonHash.Config;
import ChameleonHash.Interface.BaseIBCH;
import ChameleonHash.SchemeType;

public class BaseIBCHFactory {
    private BaseIBCHFactory() {}

    public static BaseIBCH createScheme(Config config) {
        try {
            assert config.schemeName.schemeType == SchemeType.IBCH && (!config.schemeName.has_label);
            return (BaseIBCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
