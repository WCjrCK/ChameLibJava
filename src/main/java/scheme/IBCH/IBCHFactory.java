package scheme.IBCH;

import scheme.Config;

public class IBCHFactory {
    private IBCHFactory() {}

    public static scheme.IBCH.IBCH createScheme(Config config) {
        switch (config.schemeName) {
            case IBCH_ZSS_2003_S1: return new scheme.IBCH.ZSS_2003.S1();
            case IBCH_ZSS_2003_S2: return new scheme.IBCH.ZSS_2003.S2();
            case IBCH_CZS_2014: return new scheme.IBCH.CZS_2014.Scheme();
            case IBCH_LSX_2022: return new scheme.IBCH.LSX_2022.Scheme();
            case IBCH_XSL_2021: return new scheme.IBCH.XSL_2021.Scheme();
            case IBCH_LJF_2025: return new scheme.IBCH.LJF_2025.Scheme();
        }
        throw new IllegalArgumentException("尚未支持当前方案：" + config.schemeName.name());
    }
}
