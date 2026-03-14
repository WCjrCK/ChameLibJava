package UnitTest.CHScheme;

import EllipticCurve.Curve.Config;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import ChameleonHash.IBCH.IBCHFactory;
import ChameleonHash.IBCH.ZSS_2003.PublicParam;
import ChameleonHash.IBCH.ZSS_2003.S1;
import ChameleonHash.SchemeName;

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
        ChameleonHash.Config schemeConfig = new ChameleonHash.Config(SchemeName.IBCH_ZSS_2003_S1, curveConfig, params);
        S1 scheme = (S1) IBCHFactory.createScheme(schemeConfig);

        PublicParam pp = scheme.createPublicParam(schemeConfig);
    }
}
