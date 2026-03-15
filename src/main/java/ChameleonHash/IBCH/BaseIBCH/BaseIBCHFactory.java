package ChameleonHash.IBCH.BaseIBCH;

import ChameleonHash.IBCH.IBCHConfig;
import ChameleonHash.Interface.BaseIBCH;

public class BaseIBCHFactory {
    private BaseIBCHFactory() {}

    public static BaseIBCH createScheme(IBCHConfig config) {
        try {
            assert (!config.schemeName.has_label);
            return (BaseIBCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
