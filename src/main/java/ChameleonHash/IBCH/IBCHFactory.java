package ChameleonHash.IBCH;

import ChameleonHash.Config;
import ChameleonHash.IBCH.BaseIBCH.BaseIBCHFactory;
import ChameleonHash.IBCH.LabelIBCH.LabelIBCHFactory;
import ChameleonHash.SchemeType;

public class IBCHFactory {
    private IBCHFactory() {}

    public static ChameleonHash.IBCH.IBCH createScheme(Config config) {
        try {
            assert config.schemeName.schemeType == SchemeType.IBCH;
            if (config.schemeName.has_label) return (IBCH) LabelIBCHFactory.createScheme(config);
            else return (IBCH) BaseIBCHFactory.createScheme(config);
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
