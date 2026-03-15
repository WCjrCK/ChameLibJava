package ChameleonHash.CH.LabelCH;

import ChameleonHash.CH.CHConfig;
import ChameleonHash.Interface.LabelCH;

public class LabelCHFactory {
    private LabelCHFactory() {}

    public static LabelCH createScheme(CHConfig config) {
        try {
            assert config.schemeName.has_label;
            return (LabelCH) config.schemeName.schemeClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
