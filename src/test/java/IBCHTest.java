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
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import scheme.IBCH.IBCH;
import scheme.IBCH.IB_CH_KEF_CZS_2014.MCL_swap;
import scheme.IBCH.implement.ZSS_2003.*;
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
            MasterSecretKey msk = new MasterSecretKey();
            scheme.Setup(pp, msk);
            SecretKey sk1 = new SecretKey();
            Identity ID1 = new Identity("ID1");
            scheme.KeyGen(sk1, pp, msk, ID1);

            SecretKey sk2 = new SecretKey();
            Identity ID2 = new Identity("ID2");
            scheme.KeyGen(sk2, pp, msk, ID2);

            Message m1 = new Message("msg11");
            Message m2 = new Message("msg22");

            HashValue h1 = new HashValue();
            Randomness r1 = new Randomness();
            scheme.Hash(h1, r1, pp, ID1, m1);

            assertTrue(scheme.Ver(pp, ID1, m1, h1, r1));
            assertFalse(scheme.Ver(pp, ID2, m1, h1, r1));
            assertFalse(scheme.Ver(pp, ID1, m2, h1, r1));

            HashValue h2 = new HashValue();
            Randomness r2 = new Randomness();
            scheme.Hash(h2, r2, pp, ID2, m2);

            assertTrue(scheme.Ver(pp, ID2, m2, h2, r2));
            assertFalse(scheme.Ver(pp, ID1, m2, h2, r2));
            assertFalse(scheme.Ver(pp, ID2, m1, h2, r2));
            assertFalse(scheme.Ver(pp, ID2, m2, h1, r2));
            assertFalse(scheme.Ver(pp, ID2, m2, h2, r1));

            Randomness r1_p = new Randomness();

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

    @DisplayName("test paper 《Identity-based chameleon hashing and signatures without key exposure》")
    @Nested
    class IdentityBasedChameleonHashingAndSignaturesWithoutKeyExposureTest {
        @DisplayName("test IB_CH_KEF_CZS_2014")
        @Nested
        class IB_CH_KEF_CZS_2014_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} swap_G1G2 {1}")
            @MethodSource("IBCHTest#GetPBCInvert")
            void JPBCTest(PBC curve, boolean swap_G1G2) {
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC scheme = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.PublicParam SP = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.PublicParam(curve, swap_G1G2);
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.MasterSecretKey msk = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.MasterSecretKey();
                scheme.SetUp(SP, msk);
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.SecretKey sk1 = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.SecretKey();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.SecretKey sk2 = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.SecretKey();
                Element ID1 = SP.GP.GetZrElement();
                Element ID2 = SP.GP.GetZrElement();
                assertFalse(ID1.isEqual(ID2), "ID1 != ID2");
                Element m1 = SP.GP.GetZrElement();
                Element m2 = SP.GP.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");
                Element L1 = SP.GP.GetZrElement();
                Element L2 = SP.GP.GetZrElement();
                assertFalse(L1.isEqual(L2), "L1 != L2");
                scheme.KeyGen(sk1, SP, msk, ID1);
                scheme.KeyGen(sk2, SP, msk, ID2);
                assertFalse(sk1.S_ID.isEqual(sk2.S_ID), "sk1 != sk2");

                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.HashValue h1 = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.HashValue();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.HashValue h2 = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.HashValue();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness r1 = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness r2 = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness r1_p = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness();

                scheme.Hash(h1, r1, SP, ID1, L1, m1);
                assertTrue(scheme.Check(h1, r1, SP, sk1, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, SP, sk1, L2, m1), "H(L2, m1) invalid");
                assertFalse(scheme.Check(h1, r1, SP, sk1, L1, m2), "H(L1, m2) invalid");

                scheme.Hash(h2, r2, SP, ID2, L2, m2);
                assertTrue(scheme.Check(h2, r2, SP, sk2, L2, m2), "H(L2, m2) valid");
                assertFalse(scheme.Check(h2, r2, SP, sk2, L1, m2), "H(L1, m2) invalid");
                assertFalse(scheme.Check(h2, r2, SP, sk2, L2, m1), "H(L2, m1) invalid");

                scheme.Adapt(r1_p, r1, SP, sk1, L1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, SP, sk1, L1, m2), "Adapt(L1, m2) valid");
                assertFalse(scheme.Check(h1, r1_p, SP, sk1, L1, m1), "Adapt(L1, m1) invalid");

                scheme.Adapt(r1_p, r1, SP, sk1, L2, m1, m2);
                assertFalse(scheme.Check(h1, r1_p, SP, sk1, L2, m2), "Adapt(L2, m2) invalid");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    scheme.IBCH.IB_CH_KEF_CZS_2014.MCL scheme = new scheme.IBCH.IB_CH_KEF_CZS_2014.MCL();
                    scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.PublicParam SP = new scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.PublicParam();
                    scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.MasterSecretKey msk = new scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.MasterSecretKey();
                    scheme.SetUp(SP, msk);
                    scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.SecretKey sk1 = new scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.SecretKey();
                    scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.SecretKey sk2 = new scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.SecretKey();
                    String ID1 = UUID.randomUUID().toString();
                    String ID2 = UUID.randomUUID().toString();
                    assertNotEquals(ID1, ID2, "ID1 != ID2");
                    Fr m1 = new Fr();
                    Func.GetMCLZrRandomElement(m1);
                    Fr m2 = new Fr();
                    Func.GetMCLZrRandomElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    String L1 = UUID.randomUUID().toString();
                    String L2 = UUID.randomUUID().toString();
                    assertNotEquals(L1, L2, "L1 != L2");
                    scheme.KeyGen(sk1, SP, msk, ID1);
                    scheme.KeyGen(sk2, SP, msk, ID2);
                    assertFalse(sk1.S_ID.equals(sk2.S_ID), "sk1 != sk2");

                    scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.HashValue h1 = new scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.HashValue();
                    scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.HashValue h2 = new scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.HashValue();
                    scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.Randomness r1 = new scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.Randomness();
                    scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.Randomness r2 = new scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.Randomness();
                    scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.Randomness r1_p = new scheme.IBCH.IB_CH_KEF_CZS_2014.MCL.Randomness();

                    scheme.Hash(h1, r1, SP, ID1, L1, m1);
                    assertTrue(scheme.Check(h1, r1, SP, sk1, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, SP, sk1, L2, m1), "H(L2, m1) invalid");
                    assertFalse(scheme.Check(h1, r1, SP, sk1, L1, m2), "H(L1, m2) invalid");

                    scheme.Hash(h2, r2, SP, ID2, L2, m2);
                    assertTrue(scheme.Check(h2, r2, SP, sk2, L2, m2), "H(L2, m2) valid");
                    assertFalse(scheme.Check(h2, r2, SP, sk2, L1, m2), "H(L1, m2) invalid");
                    assertFalse(scheme.Check(h2, r2, SP, sk2, L2, m1), "H(L2, m1) invalid");

                    scheme.Adapt(r1_p, r1, SP, sk1, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, sk1, L1, m2), "Adapt(L1, m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, SP, sk1, L1, m1), "Adapt(L1, m1) invalid");

                    scheme.Adapt(r1_p, r1, SP, sk1, L2, m1, m2);
                    assertFalse(scheme.Check(h1, r1_p, SP, sk1, L2, m2), "Adapt(L2, m2) invalid");
                }
                {
                    MCL_swap scheme = new MCL_swap();
                    MCL_swap.PublicParam SP = new MCL_swap.PublicParam();
                    MCL_swap.MasterSecretKey msk = new MCL_swap.MasterSecretKey();
                    scheme.SetUp(SP, msk);
                    MCL_swap.SecretKey sk1 = new MCL_swap.SecretKey();
                    MCL_swap.SecretKey sk2 = new MCL_swap.SecretKey();
                    String ID1 = UUID.randomUUID().toString();
                    String ID2 = UUID.randomUUID().toString();
                    assertNotEquals(ID1, ID2, "ID1 != ID2");
                    Fr m1 = new Fr();
                    Func.GetMCLZrRandomElement(m1);
                    Fr m2 = new Fr();
                    Func.GetMCLZrRandomElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    String L1 = UUID.randomUUID().toString();
                    String L2 = UUID.randomUUID().toString();
                    assertNotEquals(L1, L2, "L1 != L2");
                    scheme.KeyGen(sk1, SP, msk, ID1);
                    scheme.KeyGen(sk2, SP, msk, ID2);
                    assertFalse(sk1.S_ID.equals(sk2.S_ID), "sk1 != sk2");

                    MCL_swap.HashValue h1 = new MCL_swap.HashValue();
                    MCL_swap.HashValue h2 = new MCL_swap.HashValue();
                    MCL_swap.Randomness r1 = new MCL_swap.Randomness();
                    MCL_swap.Randomness r2 = new MCL_swap.Randomness();
                    MCL_swap.Randomness r1_p = new MCL_swap.Randomness();

                    scheme.Hash(h1, r1, SP, ID1, L1, m1);
                    assertTrue(scheme.Check(h1, r1, SP, sk1, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, SP, sk1, L2, m1), "H(L2, m1) invalid");
                    assertFalse(scheme.Check(h1, r1, SP, sk1, L1, m2), "H(L1, m2) invalid");

                    scheme.Hash(h2, r2, SP, ID2, L2, m2);
                    assertTrue(scheme.Check(h2, r2, SP, sk2, L2, m2), "H(L2, m2) valid");
                    assertFalse(scheme.Check(h2, r2, SP, sk2, L1, m2), "H(L1, m2) invalid");
                    assertFalse(scheme.Check(h2, r2, SP, sk2, L2, m1), "H(L2, m1) invalid");

                    scheme.Adapt(r1_p, r1, SP, sk1, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, sk1, L1, m2), "Adapt(L1, m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, SP, sk1, L1, m1), "Adapt(L1, m1) invalid");

                    scheme.Adapt(r1_p, r1, SP, sk1, L2, m1, m2);
                    assertFalse(scheme.Check(h1, r1_p, SP, sk1, L2, m2), "Adapt(L2, m2) invalid");
                }
            }
        }
    }

    @DisplayName("test paper 《Efficient Identity-Based Chameleon Hash For Mobile Devices》")
    @Nested
    class EfficientIdentityBasedChameleonHashForMobileDevicesTest {
        @DisplayName("test IB_CH_MD_LSX_2022")
        @Nested
        class IB_CH_MD_LSX_2022_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0}")
            @EnumSource(names = {"A", "A1", "E"})
            void JPBCTest(PBC curve) {
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC scheme = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.PublicParam pp = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.PublicParam(curve);
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.MasterSecretKey msk = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.MasterSecretKey();
                scheme.SetUp(pp, msk);
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.SecretKey sk1 = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.SecretKey();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.SecretKey sk2 = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.SecretKey();
                Element ID1 = pp.GP.GetZrElement();
                Element ID2 = pp.GP.GetZrElement();
                assertFalse(ID1.isEqual(ID2), "ID1 != ID2");
                Element m1 = pp.GP.GetZrElement();
                Element m2 = pp.GP.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");
                scheme.KeyGen(sk1, pp, msk, ID1);
                scheme.KeyGen(sk2, pp, msk, ID2);

                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.HashValue h1 = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.HashValue();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.HashValue h2 = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.HashValue();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness r1 = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness r2 = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness r1_p = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness();

                scheme.Hash(h1, r1, pp, ID1, m1);
                assertTrue(scheme.Check(h1, r1, pp, ID1, m1), "H(ID1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pp, ID2, m1), "H(ID2, m1) invalid");
                assertFalse(scheme.Check(h1, r1, pp, ID1, m2), "H(ID1, m2) invalid");

                scheme.Hash(h2, r2, pp, ID2, m2);
                assertTrue(scheme.Check(h2, r2, pp, ID2, m2), "H(L2, m2) valid");
                assertFalse(scheme.Check(h2, r2, pp, ID1, m2), "H(L1, m2) invalid");
                assertFalse(scheme.Check(h2, r2, pp, ID2, m1), "H(L2, m1) invalid");

                scheme.Adapt(r1_p, r1, sk1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pp, ID1, m2), "Adapt(L1, m2) valid");
                assertFalse(scheme.Check(h1, r1_p, pp, ID1, m1), "Adapt(L1, m1) invalid");
            }
        }
    }

    @DisplayName("test paper 《ID-Based Chameleon Hashes from Bilinear Pairings》")
    @Nested
    class IDBasedChameleonHashesFromBilinearPairingsTest {
        @DisplayName("test IB_CH_ZSS_S1_2003")
        @Nested
        class IB_CH_ZSS_S1_2003_Test {
        }

        @DisplayName("test IB_CH_ZSS_S2_2003")
        @Nested
        class IB_CH_ZSS_S2_2003_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0}")
            @EnumSource(names = {"A", "A1", "E"})
            void JPBCTest(PBC curve) {
                scheme.IBCH.IB_CH_ZSS_S2_2003.PBC scheme = new scheme.IBCH.IB_CH_ZSS_S2_2003.PBC();
                scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.PublicParam pp = new scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.PublicParam(curve);
                scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.MasterSecretKey msk = new scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.MasterSecretKey();
                scheme.SetUp(pp, msk);
                scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.SecretKey sk1 = new scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.SecretKey();
                scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.SecretKey sk2 = new scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.SecretKey();
                Element ID1 = pp.GP.GetZrElement();
                Element ID2 = pp.GP.GetZrElement();
                assertFalse(ID1.isEqual(ID2), "ID1 != ID2");
                Element m1 = pp.GP.GetZrElement();
                Element m2 = pp.GP.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");
                scheme.KeyGen(sk1, pp, msk, ID1);
                scheme.KeyGen(sk2, pp, msk, ID2);

                scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.HashValue h1 = new scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.HashValue();
                scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.HashValue h2 = new scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.HashValue();
                scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.Randomness r1 = new scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.Randomness();
                scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.Randomness r2 = new scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.Randomness();
                scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.Randomness r1_p = new scheme.IBCH.IB_CH_ZSS_S2_2003.PBC.Randomness();

                scheme.Hash(h1, r1, pp, ID1, m1);
                assertTrue(scheme.Check(h1, r1, pp, ID1, m1), "H(ID1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pp, ID2, m1), "H(ID2, m1) invalid");
                assertFalse(scheme.Check(h1, r1, pp, ID1, m2), "H(ID1, m2) invalid");

                scheme.Hash(h2, r2, pp, ID2, m2);
                assertTrue(scheme.Check(h2, r2, pp, ID2, m2), "H(L2, m2) valid");
                assertFalse(scheme.Check(h2, r2, pp, ID1, m2), "H(L1, m2) invalid");
                assertFalse(scheme.Check(h2, r2, pp, ID2, m1), "H(L2, m1) invalid");

                scheme.Adapt(r1_p, r1, pp, sk1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pp, ID1, m2), "Adapt(L1, m2) valid");
                assertFalse(scheme.Check(h1, r1_p, pp, ID1, m1), "Adapt(L1, m1) invalid");
            }
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
