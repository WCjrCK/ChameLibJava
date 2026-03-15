package ChameleonHash.IBCH.LabelIBCH;

import ChameleonHash.IBCH.IBCHConfig;
import ChameleonHash.Interface.LabelIBCH;

public class LabelIBCHFactory {
    private LabelIBCHFactory() {}

    public static LabelIBCH createScheme(IBCHConfig config) {
        try {
            assert config.schemeName.has_label;
            return (LabelIBCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
