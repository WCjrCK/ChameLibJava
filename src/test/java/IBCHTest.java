import EllipticCurve.Curve.CurveName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.IBCH.IBCH;
import scheme.Components.*;
import scheme.SchemeFactory;
import scheme.SchemeName;

import java.util.*;
import java.util.stream.Stream;

import static EllipticCurve.Curve.CurveName.*;
import static org.junit.jupiter.api.Assertions.*;
import static scheme.SchemeName.*;
import static scheme.SchemeName.IBCH_LSX_2022;
import static utils.Func.InitialLib;

public class IBCHTest {
    static List<SchemeName> skipList = List.of(new SchemeName[]{
            IBCH_ZSS_2003_S1,
            IBCH_ZSS_2003_S2,
            IBCH_CZS_2014,
            IBCH_LSX_2022,
            IBCH_XSL_2021,
    });

    public static Stream<Arguments> GetABSCP() {
        return EnumSet.allOf(SchemeName.class).stream().flatMap(
                a -> EnumSet.allOf(CurveName.class).stream().flatMap(b -> Stream.of(Arguments.of(a, b)))
        );
    }

    @BeforeEach
    void initTest() {
        InitialLib();
    }

    @DisplayName("test abstract impl")
    @ParameterizedTest(name = "test scheme {0} curve {1}")
    @MethodSource("IBCHTest#GetABSCP")
    void AllTest(SchemeName schemeName, CurveName curveName) {
        if (skipList.contains(schemeName)) return;
        if (curveName == SECP256K1) {
            System.out.println("MCL 库未正确实现该曲线，跳过测试");
            return;
        }
        Map<String, Object> params = new HashMap<>();
        Map<String, Object> curve_param = new HashMap<>();
        if (curveName == PBC_CUSTOM) {
            curve_param.put("param_file_path", "./jpbc/params/a.properties");
            System.out.println("利用 PBC 的 type A 曲线参数测试自定义参数模式");
        }
        params.put("curve_param", curve_param);
        params.put("ID_Binary_Len", 64);
        try {
            IBCH scheme = (IBCH) SchemeFactory.createScheme(schemeName, curveName, params);
            scheme.Components.PublicParam pp = scheme.createPublicParam(curveName, params);
            MasterSecretKey msk = scheme.createMasterSecretKey();
            scheme.Setup(pp, msk);
            SecretKey sk1 = scheme.createSecretKey();
            Identity ID1 = pp.createIdentity("ID1");
            scheme.KeyGen(sk1, pp, msk, ID1);

            SecretKey sk2 = scheme.createSecretKey();
            Identity ID2 = pp.createIdentity("ID2");
            scheme.KeyGen(sk2, pp, msk, ID2);

            Message m1 = pp.createMessage("msg11");
            Message m2 = pp.createMessage("msg22");

            HashValue h1 = scheme.createHashValue();
            Randomness r1 = scheme.createRandomness();
            scheme.Hash(h1, r1, pp, ID1, m1);

            assertTrue(scheme.Ver(pp, ID1, m1, h1, r1));
            assertFalse(scheme.Ver(pp, ID2, m1, h1, r1));
            assertFalse(scheme.Ver(pp, ID1, m2, h1, r1));

            HashValue h2 = scheme.createHashValue();
            Randomness r2 = scheme.createRandomness();
            scheme.Hash(h2, r2, pp, ID2, m2);

            assertTrue(scheme.Ver(pp, ID2, m2, h2, r2));
            assertFalse(scheme.Ver(pp, ID1, m2, h2, r2));
            assertFalse(scheme.Ver(pp, ID2, m1, h2, r2));
            assertFalse(scheme.Ver(pp, ID2, m2, h1, r2));
            assertFalse(scheme.Ver(pp, ID2, m2, h2, r1));

            Randomness r1_p = scheme.createRandomness();

            scheme.Col(r1_p, pp, ID1, sk1, m1, h1, r1, m2);
            assertTrue(scheme.Ver(pp, ID1, m1, h1, r1), "Adapt(L1, m2) valid");
            assertTrue(scheme.Ver(pp, ID1, m2, h1, r1_p), "Adapt(L1, m2) valid");
            assertFalse(scheme.Ver(pp, ID1, m1, h1, r1_p), "Adapt(L1, m1) invalid");
        } catch (IllegalArgumentException e) {
            if(e.getMessage().contains("不支持")) {
                System.out.println(e.getMessage());
                return;
            }
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
