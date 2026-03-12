package scheme.IBCH;

import scheme.IBCH.implement.ZSS_2003.S1;
import scheme.IBCH.implement.ZSS_2003.S2;
import scheme.Scheme;
import scheme.SchemeName;

import java.util.Map;

public class IBCHFactory {
    private IBCHFactory() {}

    public static Scheme createScheme(SchemeName schemeName, Map<String, Object> params) {
        switch (schemeName) {
            case IBCH_ZSS_2003_S1: return new S1();
            case IBCH_ZSS_2003_S2: return new S2();
            case IBCH_CZS_2014: return new scheme.IBCH.implement.CZS_2014.Scheme();
        }
        throw new IllegalArgumentException("尚未支持当前方案：" + schemeName.name());
    }
}
