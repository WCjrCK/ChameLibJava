import it.unisa.dia.gas.jpbc.Element;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

public class IBCHTest {
    public static Stream<Arguments> GetPBCInvert() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a -> Stream.of(Arguments.of(a, false), Arguments.of(a, true)));
    }

    public static Stream<Arguments> GetPBCInvertIdentityLen() {
        List<Integer> IdentityLen = Arrays.asList(64, 128, 256);
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a -> IdentityLen.stream().flatMap(b -> Stream.of(Arguments.of(a, b, false), Arguments.of(a, b, true))));
    }

    @BeforeEach
    void initTest() {
        InitialLib();
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
            void JPBCTest(curve.PBC curve, boolean swap_G1G2) {
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
            void JPBCTest(curve.PBC curve) {
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
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} swap_G1G2 {1}")
            @MethodSource("IBCHTest#GetPBCInvert")
            void JPBCTest(curve.PBC curve, boolean swap_G1G2) {
                scheme.IBCH.IB_CH_ZSS_S1_2003.PBC scheme = new scheme.IBCH.IB_CH_ZSS_S1_2003.PBC();
                scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.PublicParam SP = new scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.PublicParam(curve, swap_G1G2);
                scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.MasterSecretKey msk = new scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.MasterSecretKey();
                scheme.SetUp(SP, msk);
                scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.SecretKey sk1 = new scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.SecretKey();
                scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.SecretKey sk2 = new scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.SecretKey();
                Element ID1 = SP.GP.GetZrElement();
                Element ID2 = SP.GP.GetZrElement();
                assertFalse(ID1.isEqual(ID2), "ID1 != ID2");
                Element m1 = SP.GP.GetZrElement();
                Element m2 = SP.GP.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");
                scheme.KeyGen(sk1, SP, msk, ID1);
                scheme.KeyGen(sk2, SP, msk, ID2);

                scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.HashValue h1 = new scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.HashValue();
                scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.HashValue h2 = new scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.HashValue();
                scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.Randomness r1 = new scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.Randomness();
                scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.Randomness r2 = new scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.Randomness();
                scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.Randomness r1_p = new scheme.IBCH.IB_CH_ZSS_S1_2003.PBC.Randomness();

                scheme.Hash(h1, r1, SP, ID1, m1);
                assertTrue(scheme.Check(h1, r1, SP, ID1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, SP, ID2, m1), "H(L2, m1) invalid");
                assertFalse(scheme.Check(h1, r1, SP, ID1, m2), "H(L1, m2) invalid");

                scheme.Hash(h2, r2, SP, ID2, m2);
                assertTrue(scheme.Check(h2, r2, SP, ID2, m2), "H(L2, m2) valid");
                assertFalse(scheme.Check(h2, r2, SP, ID1, m2), "H(L1, m2) invalid");
                assertFalse(scheme.Check(h2, r2, SP, ID2, m1), "H(L2, m1) invalid");

                scheme.Adapt(r1_p, r1, SP, sk1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, SP, ID1, m2), "Adapt(L1, m2) valid");
                assertFalse(scheme.Check(h1, r1_p, SP, ID1, m1), "Adapt(L1, m1) invalid");
            }
        }

        @DisplayName("test IB_CH_ZSS_S2_2003")
        @Nested
        class IB_CH_ZSS_S2_2003_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0}")
            @EnumSource(names = {"A", "A1", "E"})
            void JPBCTest(curve.PBC curve) {
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
            void JPBCTest(curve.PBC curve, int n, boolean swap_G1G2) {
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
        }
    }
}
