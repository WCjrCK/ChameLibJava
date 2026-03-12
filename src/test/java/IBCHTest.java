import EllipticCurve.Curve.CurveName;
import com.herumi.mcl.Fr;
import curve.MCL;
import curve.PBC;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.IBCH.IBCH;
import scheme.Components.*;
import scheme.SchemeFactory;
import scheme.SchemeName;
import utils.Func;

import java.util.*;
import java.util.stream.Stream;

import static EllipticCurve.Curve.CurveName.*;
import static org.junit.jupiter.api.Assertions.*;
import static utils.Func.InitialLib;

public class IBCHTest {
    public static Stream<Arguments> GetPBCInvert() {
        return EnumSet.allOf(PBC.class).stream().flatMap(a -> Stream.of(Arguments.of(a, false), Arguments.of(a, true)));
    }

    public static Stream<Arguments> GetPBCInvertIdentityLen() {
        List<Integer> IdentityLen = Arrays.asList(64, 128, 256);
        return EnumSet.allOf(PBC.class).stream().flatMap(a -> IdentityLen.stream().flatMap(b -> Stream.of(Arguments.of(a, b, false), Arguments.of(a, b, true))));
    }

    public static Stream<Arguments> GetMCLInvertIdentityLen() {
        List<Integer> IdentityLen = Arrays.asList(64, 128, 256);
        List<MCL> curves = Arrays.asList(MCL.BN254, MCL.BLS12_381);
        return curves.stream().flatMap(a -> IdentityLen.stream().flatMap(b -> Stream.of(Arguments.of(a, b))));
    }

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
    void ABSTest(SchemeName schemeName, CurveName curveName) {
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

    @DisplayName("test paper 《Identity-Based Chameleon Hash without Random Oracles and Application in the Mobile Internet》")
    @Nested
    class IdentityBasedChameleonHashWithoutRandomOraclesAndApplicationInTheMobileInternetTest {
        @DisplayName("test ID_B_CollRes_XSL_2021")
        @Nested
        class ID_B_CollRes_XSL_2021_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0}, Identity len = {1}, swap_G1G2 {2}")
            @MethodSource("IBCHTest#GetPBCInvertIdentityLen")
            void JPBCTest(PBC curve, int n, boolean swap_G1G2) {
                scheme.IBCH.ID_B_CollRes_XSL_2021.PBC scheme = new scheme.IBCH.ID_B_CollRes_XSL_2021.PBC();
                scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.PublicParam SP = new scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.PublicParam(curve, swap_G1G2, n);
                scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.MasterSecretKey msk = new scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.MasterSecretKey();
                scheme.SetUp(SP, msk);
                scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.SecretKey sk1 = new scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.SecretKey();
                scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.SecretKey sk2 = new scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.SecretKey();
                scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.Identity ID1 = SP.GenIdentity();
                scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.Identity ID2 = SP.GenIdentity();
                Element m1 = SP.GP.GetZrElement();
                Element m2 = SP.GP.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");
                scheme.KeyGen(sk1, SP, msk, ID1);
                scheme.KeyGen(sk2, SP, msk, ID2);

                scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.HashValue h1 = new scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.HashValue();
                scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.HashValue h2 = new scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.HashValue();
                scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.Randomness r1 = new scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.Randomness();
                scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.Randomness r2 = new scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.Randomness();
                scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.Randomness r1_p = new scheme.IBCH.ID_B_CollRes_XSL_2021.PBC.Randomness();

                scheme.Hash(h1, r1, SP, ID1, m1);
                assertTrue(scheme.Check(h1, r1, SP, ID1, m1), "H(ID1, m1) valid");
                assertFalse(scheme.Check(h1, r1, SP, ID2, m1), "H(ID2, m1) invalid");
                assertFalse(scheme.Check(h1, r1, SP, ID1, m2), "H(ID1, m2) invalid");

                scheme.Hash(h2, r2, SP, ID2, m2);
                assertTrue(scheme.Check(h2, r2, SP, ID2, m2), "H(ID2, m2) valid");
                assertFalse(scheme.Check(h2, r2, SP, ID1, m2), "H(ID1, m2) invalid");
                assertFalse(scheme.Check(h2, r2, SP, ID2, m1), "H(ID2, m1) invalid");

                scheme.Adapt(r1_p, r1, sk1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, SP, ID1, m2), "Adapt(ID1, m2) valid");
                assertFalse(scheme.Check(h1, r1_p, SP, ID1, m1), "Adapt(ID1, m1) invalid");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
//            @EnumSource(names = {"BN254", "BLS12_381"})
            @MethodSource("IBCHTest#GetMCLInvertIdentityLen")
            void MCLTest(MCL curve, int n) {
                Func.MCLInit(curve);
                {
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL scheme = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.PublicParam SP = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.PublicParam(n);
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.MasterSecretKey msk = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.MasterSecretKey();
                    scheme.SetUp(SP, msk);
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.SecretKey sk1 = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.SecretKey();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.SecretKey sk2 = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.SecretKey();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.Identity ID1 = SP.GenIdentity();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.Identity ID2 = SP.GenIdentity();
                    Fr m1 = new Fr();
                    Func.GetMCLZrRandomElement(m1);
                    Fr m2 = new Fr();
                    Func.GetMCLZrRandomElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    scheme.KeyGen(sk1, SP, msk, ID1);
                    scheme.KeyGen(sk2, SP, msk, ID2);

                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.HashValue h1 = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.HashValue();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.HashValue h2 = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.HashValue();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.Randomness r1 = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.Randomness();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.Randomness r2 = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.Randomness();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.Randomness r1_p = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL.Randomness();

                    scheme.Hash(h1, r1, SP, ID1, m1);
                    assertTrue(scheme.Check(h1, r1, SP, ID1, m1), "H(ID1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, SP, ID2, m1), "H(ID2, m1) invalid");
                    assertFalse(scheme.Check(h1, r1, SP, ID1, m2), "H(ID1, m2) invalid");

                    scheme.Hash(h2, r2, SP, ID2, m2);
                    assertTrue(scheme.Check(h2, r2, SP, ID2, m2), "H(ID2, m2) valid");
                    assertFalse(scheme.Check(h2, r2, SP, ID1, m2), "H(ID1, m2) invalid");
                    assertFalse(scheme.Check(h2, r2, SP, ID2, m1), "H(ID2, m1) invalid");

                    scheme.Adapt(r1_p, r1, sk1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, ID1, m2), "Adapt(ID1, m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, SP, ID1, m1), "Adapt(ID1, m1) invalid");
                }
                {
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap scheme = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.PublicParam SP = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.PublicParam(n);
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.MasterSecretKey msk = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.MasterSecretKey();
                    scheme.SetUp(SP, msk);
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.SecretKey sk1 = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.SecretKey();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.SecretKey sk2 = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.SecretKey();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.Identity ID1 = SP.GenIdentity();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.Identity ID2 = SP.GenIdentity();
                    Fr m1 = new Fr();
                    Func.GetMCLZrRandomElement(m1);
                    Fr m2 = new Fr();
                    Func.GetMCLZrRandomElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    scheme.KeyGen(sk1, SP, msk, ID1);
                    scheme.KeyGen(sk2, SP, msk, ID2);

                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.HashValue h1 = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.HashValue();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.HashValue h2 = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.HashValue();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.Randomness r1 = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.Randomness();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.Randomness r2 = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.Randomness();
                    scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.Randomness r1_p = new scheme.IBCH.ID_B_CollRes_XSL_2021.MCL_swap.Randomness();

                    scheme.Hash(h1, r1, SP, ID1, m1);
                    assertTrue(scheme.Check(h1, r1, SP, ID1, m1), "H(ID1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, SP, ID2, m1), "H(ID2, m1) invalid");
                    assertFalse(scheme.Check(h1, r1, SP, ID1, m2), "H(ID1, m2) invalid");

                    scheme.Hash(h2, r2, SP, ID2, m2);
                    assertTrue(scheme.Check(h2, r2, SP, ID2, m2), "H(ID2, m2) valid");
                    assertFalse(scheme.Check(h2, r2, SP, ID1, m2), "H(ID1, m2) invalid");
                    assertFalse(scheme.Check(h2, r2, SP, ID2, m1), "H(ID2, m1) invalid");

                    scheme.Adapt(r1_p, r1, sk1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, ID1, m2), "Adapt(ID1, m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, SP, ID1, m1), "Adapt(ID1, m1) invalid");
                }
            }
        }
    }
}
