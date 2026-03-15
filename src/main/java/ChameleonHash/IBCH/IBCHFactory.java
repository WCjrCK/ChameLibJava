package ChameleonHash.IBCH;

import ChameleonHash.IBCH.BaseIBCH.BaseIBCHFactory;
import ChameleonHash.IBCH.LabelIBCH.LabelIBCHFactory;

public class IBCHFactory {
    private IBCHFactory() {}

    public static ChameleonHash.IBCH.IBCH createScheme(IBCHConfig config) {
        try {
            if (config.schemeName.has_label) return (IBCH) LabelIBCHFactory.createScheme(config);
            else return (IBCH) BaseIBCHFactory.createScheme(config);
        } catch (Exception e) {
            throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
        }
    }
}
