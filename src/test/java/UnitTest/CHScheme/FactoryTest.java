package UnitTest.CHScheme;

import EllipticCurve.Curve.Config;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import scheme.IBCH.IBCHFactory;
import scheme.IBCH.ZSS_2003.PublicParam;
import scheme.IBCH.ZSS_2003.S1;
import scheme.SchemeName;

import java.util.HashMap;
import java.util.Map;

import static EllipticCurve.Curve.CurveName.E;

public class FactoryTest {

    @DisplayName("test mismatch type")
    @Test
    void IBCHWrongTypeTest() {
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
        params.put("ID_Binary_Len", 64);
        Config curveConfig = new Config(E, curve_param);
        scheme.Config schemeConfig = new scheme.Config(SchemeName.IBCH_ZSS_2003_S1, curveConfig, params);
        S1 scheme = (S1) IBCHFactory.createScheme(schemeConfig);

        PublicParam pp = scheme.createPublicParam(schemeConfig);
    }
}
