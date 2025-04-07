import com.herumi.mcl.*;
import curve.Group;
import curve.MCL;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import utils.Func;

import java.math.BigInteger;
import java.util.EnumSet;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

@SuppressWarnings("rawtypes")
public class CHTest {
    public static Stream<Arguments> GetPBCCartesianProduct() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a -> EnumSet.allOf(Group.class).stream().flatMap(b -> Stream.of(Arguments.of(a, b))));
    }

    @BeforeEach
    void initTest() {
        InitialLib();
    }

    @DisplayName("test NIZK")
    @Nested
    class NIZKTest {
        @DisplayName("test PBC impl")
        @ParameterizedTest(name = "test curve {0} group {1}")
        @MethodSource("CHTest#GetPBCCartesianProduct")
        void JPBCTest(curve.PBC curve, Group group) {
            Pairing pairing = Func.PairingGen(curve);
            Field G = Func.GetPBCField(pairing, group);
            Field Zr = pairing.getZr();

            Element x1 = Zr.newRandomElement().getImmutable();
            Element g1 = G.newRandomElement().getImmutable();
            Element y1 = g1.powZn(x1).getImmutable();
            Element yt = G.newRandomElement().getImmutable();

            base.NIZK.PBC.DL_Proof pi1 = new base.NIZK.PBC.DL_Proof(Zr, x1, g1, y1);

            assertTrue(pi1.Check(g1, y1), "proof pass");
            assertFalse(pi1.Check(g1, yt), "proof fail");

            Element g2 = G.newRandomElement().getImmutable();
            Element y2 = g2.powZn(x1).getImmutable();

            base.NIZK.PBC.EQUAL_DL_Proof pi2 = new base.NIZK.PBC.EQUAL_DL_Proof(Zr, x1, g1, y1, g2, y2);

            assertTrue(pi2.Check(g1, y1, g2, y2), "proof pass");
            assertFalse(pi2.Check(g1, yt, g2, y2), "proof fail");
            assertFalse(pi2.Check(g1, y1, g2, yt), "proof fail");
            assertFalse(pi2.Check(g1, y2, g2, y1), "proof fail");

            base.NIZK.PBC.DH_PAIR_Proof pi4 = new base.NIZK.PBC.DH_PAIR_Proof(Zr, x1, g1, y1, g2, y2, Func.GetNdonr(group, Func.PairingParam(curve)));

            assertTrue(pi4.Check(g1, y1, g2, y2), "proof pass");
            assertFalse(pi4.Check(g1, yt, g2, y2), "proof fail");
            assertFalse(pi4.Check(g1, y1, g2, yt), "proof fail");
            assertFalse(pi4.Check(g1, y2, g2, y1), "proof fail");

            Element x2 = Zr.newRandomElement().getImmutable();
            y2 = g2.powZn(x2).getImmutable();
            Element y3 = y1.mul(y2).getImmutable();

            base.NIZK.PBC.REPRESENT_Proof pi3 = new base.NIZK.PBC.REPRESENT_Proof(Zr, y3, g1, x1, g2, x2);

            assertTrue(pi3.Check(y3, g1, g2), "proof pass");
            assertFalse(pi3.Check(y3, g1, yt), "proof fail");
            assertFalse(pi3.Check(y3, g2, g1), "proof fail");
        }

        @DisplayName("test MCL impl")
        @ParameterizedTest(name = "test curve {0}")
        // BadCaseTest#MCL_Bad_Case#Case2
        @EnumSource(names = {"BN254", "BLS12_381"})
        @SuppressWarnings("SuspiciousNameCombination")
        void MCLTest(MCL curve) {
            Func.MCLInit(curve);
            G1[] G1_tmp = new G1[]{new G1(), new G1(), new G1()};
            G2[] G2_tmp = new G2[]{new G2(), new G2(), new G2()};
            GT[] GT_tmp = new GT[]{new GT(), new GT(), new GT()};
            Fr[] Fr_tmp = new Fr[]{new Fr(), new Fr(), new Fr()};
            {
                Fr x1 = new Fr();
                Func.GetMCLZrRandomElement(x1);
                G1 g1 = new G1();
                Func.GetMCLG1RandomElement(g1);
                G1 y1 = new G1();
                Mcl.mul(y1, g1, x1);
                G1 yt = new G1();
                Func.GetMCLG1RandomElement(yt);

                base.NIZK.MCL_G1.DL_Proof pi1 = new base.NIZK.MCL_G1.DL_Proof(x1, g1, y1, Fr_tmp);

                assertTrue(pi1.Check(g1, y1, G1_tmp, Fr_tmp), "proof pass");
                assertFalse(pi1.Check(g1, yt, G1_tmp, Fr_tmp), "proof fail");

                G1 g2 = new G1();
                Func.GetMCLG1RandomElement(g2);
                G1 y2 = new G1();
                Mcl.mul(y2, g2, x1);

                base.NIZK.MCL_G1.EQUAL_DL_Proof pi2 = new base.NIZK.MCL_G1.EQUAL_DL_Proof(x1, g1, y1, g2, y2, Fr_tmp);

                assertTrue(pi2.Check(g1, y1, g2, y2, G1_tmp, Fr_tmp), "proof pass");
                assertFalse(pi2.Check(g1, yt, g2, y2, G1_tmp, Fr_tmp), "proof fail");
                assertFalse(pi2.Check(g1, y1, g2, yt, G1_tmp, Fr_tmp), "proof fail");
                assertFalse(pi2.Check(g1, y2, g2, y1, G1_tmp, Fr_tmp), "proof fail");

                base.NIZK.MCL_G1.DH_PAIR_Proof pi4 = new base.NIZK.MCL_G1.DH_PAIR_Proof(x1, g1, y1, g2, y2, G1_tmp, Fr_tmp);

                assertTrue(pi4.Check(g1, y1, g2, y2, G1_tmp, Fr_tmp), "proof pass");
                assertFalse(pi4.Check(g1, yt, g2, y2, G1_tmp, Fr_tmp), "proof fail");
                assertFalse(pi4.Check(g1, y1, g2, yt, G1_tmp, Fr_tmp), "proof fail");
                assertFalse(pi4.Check(g1, y2, g2, y1, G1_tmp, Fr_tmp), "proof fail");

                Fr x2 = new Fr();
                Func.GetMCLZrRandomElement(x2);
                Mcl.mul(y2, g2, x2);
                G1 y3 = new G1();
                Mcl.add(y3, y1, y2);

                base.NIZK.MCL_G1.REPRESENT_Proof pi3 = new base.NIZK.MCL_G1.REPRESENT_Proof(y3, g1, x1, g2, x2, G1_tmp, Fr_tmp);

                assertTrue(pi3.Check(y3, g1, g2, G1_tmp, Fr_tmp), "proof pass");
                assertFalse(pi3.Check(y3, g1, yt, G1_tmp, Fr_tmp), "proof fail");
                assertFalse(pi3.Check(y3, g2, g1, G1_tmp, Fr_tmp), "proof fail");
            }
            if(curve != MCL.SECP256K1) {
                // BadCaseTest#MCL_Bad_Case#Case1
                Fr x1 = new Fr();
                Func.GetMCLZrRandomElement(x1);
                G2 g1 = new G2();
                Func.GetMCLG2RandomElement(g1);
                G2 y1 = new G2();
                Mcl.mul(y1, g1, x1);
                G2 yt = new G2();
                Func.GetMCLG2RandomElement(yt);

                base.NIZK.MCL_G2.DL_Proof pi1 = new base.NIZK.MCL_G2.DL_Proof(x1, g1, y1, Fr_tmp);

                assertTrue(pi1.Check(g1, y1, G2_tmp, Fr_tmp), "proof pass");
                assertFalse(pi1.Check(g1, yt, G2_tmp, Fr_tmp), "proof fail");

                G2 g2 = new G2();
                Func.GetMCLG2RandomElement(g2);
                G2 y2 = new G2();
                Mcl.mul(y2, g2, x1);

                base.NIZK.MCL_G2.EQUAL_DL_Proof pi2 = new base.NIZK.MCL_G2.EQUAL_DL_Proof(x1, g1, y1, g2, y2, Fr_tmp);

                assertTrue(pi2.Check(g1, y1, g2, y2, G2_tmp, Fr_tmp), "proof pass");
                assertFalse(pi2.Check(g1, yt, g2, y2, G2_tmp, Fr_tmp), "proof fail");
                assertFalse(pi2.Check(g1, y1, g2, yt, G2_tmp, Fr_tmp), "proof fail");
                assertFalse(pi2.Check(g1, y2, g2, y1, G2_tmp, Fr_tmp), "proof fail");

                base.NIZK.MCL_G2.DH_PAIR_Proof pi4 = new base.NIZK.MCL_G2.DH_PAIR_Proof(x1, g1, y1, g2, y2, G2_tmp, Fr_tmp);

                assertTrue(pi4.Check(g1, y1, g2, y2, G2_tmp, Fr_tmp), "proof pass");
                assertFalse(pi4.Check(g1, yt, g2, y2, G2_tmp, Fr_tmp), "proof fail");
                assertFalse(pi4.Check(g1, y1, g2, yt, G2_tmp, Fr_tmp), "proof fail");
                assertFalse(pi4.Check(g1, y2, g2, y1, G2_tmp, Fr_tmp), "proof fail");

                Fr x2 = new Fr();
                Func.GetMCLZrRandomElement(x2);
                Mcl.mul(y2, g2, x2);
                G2 y3 = new G2();
                Mcl.add(y3, y1, y2);

                base.NIZK.MCL_G2.REPRESENT_Proof pi3 = new base.NIZK.MCL_G2.REPRESENT_Proof(y3, g1, x1, g2, x2, G2_tmp, Fr_tmp);

                assertTrue(pi3.Check(y3, g1, g2, G2_tmp, Fr_tmp), "proof pass");
                assertFalse(pi3.Check(y3, g1, yt, G2_tmp, Fr_tmp), "proof fail");
                assertFalse(pi3.Check(y3, g2, g1, G2_tmp, Fr_tmp), "proof fail");
            }

            {
                // BadCaseTest#MCL_Bad_Case#Case1
                Fr x1 = new Fr();
                Func.GetMCLZrRandomElement(x1);
                GT g1 = new GT();
                Func.GetMCLGTRandomElement(g1);
                GT y1 = new GT();
                Mcl.pow(y1, g1, x1);
                GT yt = new GT();
                Func.GetMCLGTRandomElement(yt);

                base.NIZK.MCL_GT.DL_Proof pi1 = new base.NIZK.MCL_GT.DL_Proof(x1, g1, y1, Fr_tmp);

                assertTrue(pi1.Check(g1, y1, GT_tmp, Fr_tmp), "proof pass");
                assertFalse(pi1.Check(g1, yt, GT_tmp, Fr_tmp), "proof fail");

                GT g2 = new GT();
                Func.GetMCLGTRandomElement(g2);
                GT y2 = new GT();
                Mcl.pow(y2, g2, x1);

                base.NIZK.MCL_GT.EQUAL_DL_Proof pi2 = new base.NIZK.MCL_GT.EQUAL_DL_Proof(x1, g1, y1, g2, y2, Fr_tmp);

                assertTrue(pi2.Check(g1, y1, g2, y2, GT_tmp, Fr_tmp), "proof pass");
                assertFalse(pi2.Check(g1, yt, g2, y2, GT_tmp, Fr_tmp), "proof fail");
                assertFalse(pi2.Check(g1, y1, g2, yt, GT_tmp, Fr_tmp), "proof fail");
                assertFalse(pi2.Check(g1, y2, g2, y1, GT_tmp, Fr_tmp), "proof fail");

                base.NIZK.MCL_GT.DH_PAIR_Proof pi4 = new base.NIZK.MCL_GT.DH_PAIR_Proof(x1, g1, y1, g2, y2, GT_tmp, Fr_tmp);

                assertTrue(pi4.Check(g1, y1, g2, y2, GT_tmp, Fr_tmp), "proof pass");
                assertFalse(pi4.Check(g1, yt, g2, y2, GT_tmp, Fr_tmp), "proof fail");
                assertFalse(pi4.Check(g1, y1, g2, yt, GT_tmp, Fr_tmp), "proof fail");
                assertFalse(pi4.Check(g1, y2, g2, y1, GT_tmp, Fr_tmp), "proof fail");

                Fr x2 = new Fr();
                Func.GetMCLZrRandomElement(x2);
                Mcl.pow(y2, g2, x2);
                GT y3 = new GT();
                Mcl.mul(y3, y1, y2);

                base.NIZK.MCL_GT.REPRESENT_Proof pi3 = new base.NIZK.MCL_GT.REPRESENT_Proof(y3, g1, x1, g2, x2, GT_tmp, Fr_tmp);

                assertTrue(pi3.Check(y3, g1, g2, GT_tmp, Fr_tmp), "proof pass");
                assertFalse(pi3.Check(y3, g1, yt, GT_tmp, Fr_tmp), "proof fail");
                assertFalse(pi3.Check(y3, g2, g1, GT_tmp, Fr_tmp), "proof fail");
            }
        }
    }

    @DisplayName("test paper 《On the Key Exposure Problem in Chameleon Hashes》")
    @Nested
    class OnTheKeyExposureProblemInChameleonHashesTest {
        @DisplayName("test CH_KEF_NoMH_AM_2004")
        @Nested
        class CH_KEF_NoMH_AM_2004_Test {
            @DisplayName("test native impl")
            @Test
            void NativeTest() {
                Random rand = new Random();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native scheme = new scheme.CH.CH_KEF_NoMH_AM_2004.Native();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.PublicKey pk = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.PublicKey();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.SecretKey sk = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.SecretKey();
                scheme.KeyGen(pk, sk, 512);
                BigInteger m1 = new BigInteger(256, rand);
                BigInteger m2 = new BigInteger(256, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.HashValue h1 = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.HashValue();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.HashValue h2 = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.HashValue();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.Randomness r1 = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.Randomness();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.Randomness r2 = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.Randomness();
                scheme.CH.CH_KEF_NoMH_AM_2004.Native.Randomness r1_p = new scheme.CH.CH_KEF_NoMH_AM_2004.Native.Randomness();
                scheme.Hash(h1, r1, pk, m1);
                assertTrue(scheme.Check(h1, r1, pk, m1), "H(m1) valid");
                scheme.Hash(h2, r2, pk, m2);
                assertTrue(scheme.Check(h2, r2, pk, m2), "H(m2) valid");

                assertFalse(scheme.Check(h1, r1, pk, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, pk, sk, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, m2), "Adapt(m2) valid");
            }
        }

        @DisplayName("test CH_KEF_MH_RSA_F_AM_2004")
        @Nested
        class CH_KEF_MH_RSA_F_AM_2004_Test {
            @DisplayName("test native impl")
            @Test
            void NativeTest() {
                Random rand = new Random();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native scheme = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.PublicParam pp = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.PublicParam();
                scheme.SetUp(pp, 512, 1024);
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.PublicKey pk = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.PublicKey();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.SecretKey sk = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.SecretKey();
                scheme.KeyGen(pk, sk, pp);
                BigInteger m1 = new BigInteger(256, rand);
                BigInteger m2 = new BigInteger(256, rand);
                BigInteger L1 = new BigInteger(512, rand);
                BigInteger L2 = new BigInteger(512, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.HashValue h1 = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.HashValue();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.HashValue h2 = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.HashValue();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness r1 = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness r2 = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness();
                scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness r1_p = new scheme.CH.CH_KEF_MH_RSA_F_AM_2004.Native.Randomness();
                scheme.Hash(h1, r1, pk, L1, m1, pp);
                assertTrue(scheme.Check(h1, r1, pk, L1, m1, pp), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pk, L2, m1, pp), "not H(L2, m1)");
                scheme.Hash(h2, r2, pk, L2, m2, pp);
                assertTrue(scheme.Check(h2, r2, pk, L2, m2, pp), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pk, L1, m2, pp), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, pk, L2, m2, pp), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, L1, m1, pp), "not H(m2)");

                scheme.Adapt(r1_p, r1, pk, sk, L1, m1, m2, pp);
                assertTrue(scheme.Check(h1, r1_p, pk, L1, m2, pp), "Adapt(m2) valid");

                scheme.Adapt(r1_p, r1, pk, sk, L2, m1, m2, pp);
                assertFalse(scheme.Check(h1, r1_p, pk, L2, m2, pp), "not Adapt(m2)");
            }
        }

        @DisplayName("test CH_KEF_MH_RSANN_F_AM_2004")
        @Nested
        class CH_KEF_MH_RSANN_F_AM_2004_Test {
            @DisplayName("test native impl")
            @Test
            void NativeTest() {
                Random rand = new Random();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native scheme = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.PublicKey pk = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.PublicKey();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.SecretKey sk = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.SecretKey();
                scheme.KeyGen(pk, sk, 512);
                BigInteger m1 = new BigInteger(256, rand);
                BigInteger m2 = new BigInteger(256, rand);
                BigInteger L1 = new BigInteger(512, rand);
                BigInteger L2 = new BigInteger(512, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.HashValue h1 = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.HashValue();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.HashValue h2 = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.HashValue();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness r1 = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness r2 = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness();
                scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness r1_p = new scheme.CH.CH_KEF_MH_RSANN_F_AM_2004.Native.Randomness();
                scheme.Hash(h1, r1, pk, L1, m1);
                assertTrue(scheme.Check(h1, r1, pk, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pk, L2, m1), "not H(L2, m1)");
                scheme.Hash(h2, r2, pk, L2, m2);
                assertTrue(scheme.Check(h2, r2, pk, L2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pk, L1, m2), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, pk, L2, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, L1, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, pk, sk, L1, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, L1, m2), "Adapt(m2) valid");

    //            scheme.Adapt(r1_p, h1, pk, sk, L2, m2);
    //            assertFalse(scheme.Check(h1, r1_p, pk, L2, m2), "not Adapt(m2)");
            }
        }

        @DisplayName("test CH_KEF_MH_SDH_DL_AM_2004")
        @Nested
        class CH_KEF_MH_SDH_DL_AM_2004_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC scheme = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.PublicParam pp = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.PublicParam(curve, group);
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.PublicKey pk = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.PublicKey();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.SecretKey sk = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.SecretKey();
                scheme.KeyGen(pk, sk, pp);
                Element m1 = pp.GP.GetZrElement();
                Element m2 = pp.GP.GetZrElement();
                Element L1 = pp.GP.GetZrElement();
                Element L2 = pp.GP.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");

                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.HashValue h1 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.HashValue();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.HashValue h2 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.HashValue();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness r1 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness r2 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness();
                scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness r1_p = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.PBC.Randomness();
                scheme.Hash(h1, r1, pp, pk, L1, m1);
                assertTrue(scheme.Check(h1, r1, pp, pk, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pp, pk, L2, m1), "not H(L2, m1)");
                scheme.Hash(h2, r2, pp, pk, L2, m2);
                assertTrue(scheme.Check(h2, r2, pp, pk, L2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pp, pk, L1, m2), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, pp, pk, L2, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pp, pk, L1, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, r1, pp, pk, sk, L1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pp, pk, L1, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, pp, pk, L2, m2), "not L2");

                scheme.Adapt(r1_p, h2, r2, pp, pk, sk, L2, m2, m1);
                assertTrue(scheme.Check(h2, r1_p, pp, pk, L2, m1), "Adapt(m1) valid");
                assertFalse(scheme.Check(h2, r1_p, pp, pk, L1, m1), "not L1");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
//            @EnumSource(MCL.class)
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1 scheme = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.PublicParam pp = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.PublicParam();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.PublicKey pk = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.PublicKey();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.SecretKey sk = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    Fr L1 = new Fr();
                    pp.GP.GetZrElement(L1);
                    Fr L2 = new Fr();
                    pp.GP.GetZrElement(L2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.HashValue h1 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.HashValue();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.HashValue h2 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.HashValue();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.Randomness r1 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.Randomness();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.Randomness r2 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.Randomness();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.Randomness r1_p = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G1.Randomness();
                    scheme.Hash(h1, r1, pp, pk, L1, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, L2, m1), "not H(L2, m1)");
                    scheme.Hash(h2, r2, pp, pk, L2, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, pp, pk, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, pp, pk, L1, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, L1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, L2, m2), "not L2");

                    scheme.Adapt(r1_p, h2, r2, pp, pk, sk, L2, m2, m1);
                    assertTrue(scheme.Check(h2, r1_p, pp, pk, L2, m1), "Adapt(m1) valid");
                    assertFalse(scheme.Check(h2, r1_p, pp, pk, L1, m1), "not L1");
                }
                {
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2 scheme = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.PublicParam pp = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.PublicParam();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.PublicKey pk = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.PublicKey();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.SecretKey sk = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    Fr L1 = new Fr();
                    pp.GP.GetZrElement(L1);
                    Fr L2 = new Fr();
                    pp.GP.GetZrElement(L2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.HashValue h1 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.HashValue();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.HashValue h2 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.HashValue();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.Randomness r1 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.Randomness();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.Randomness r2 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.Randomness();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.Randomness r1_p = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_G2.Randomness();
                    scheme.Hash(h1, r1, pp, pk, L1, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, L2, m1), "not H(L2, m1)");
                    scheme.Hash(h2, r2, pp, pk, L2, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, pp, pk, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, pp, pk, L1, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, L1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, L2, m2), "not L2");

                    scheme.Adapt(r1_p, h2, r2, pp, pk, sk, L2, m2, m1);
                    assertTrue(scheme.Check(h2, r1_p, pp, pk, L2, m1), "Adapt(m1) valid");
                    assertFalse(scheme.Check(h2, r1_p, pp, pk, L1, m1), "not L1");
                }
                {
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT scheme = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.PublicParam pp = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.PublicParam();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.PublicKey pk = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.PublicKey();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.SecretKey sk = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    Fr L1 = new Fr();
                    pp.GP.GetZrElement(L1);
                    Fr L2 = new Fr();
                    pp.GP.GetZrElement(L2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.HashValue h1 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.HashValue();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.HashValue h2 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.HashValue();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.Randomness r1 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.Randomness();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.Randomness r2 = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.Randomness();
                    scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.Randomness r1_p = new scheme.CH.CH_KEF_MH_SDH_DL_AM_2004.MCL_GT.Randomness();
                    scheme.Hash(h1, r1, pp, pk, L1, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, L2, m1), "not H(L2, m1)");
                    scheme.Hash(h2, r2, pp, pk, L2, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, pp, pk, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, pp, pk, L1, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, L1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, L2, m2), "not L2");

                    scheme.Adapt(r1_p, h2, r2, pp, pk, sk, L2, m2, m1);
                    assertTrue(scheme.Check(h2, r1_p, pp, pk, L2, m1), "Adapt(m1) valid");
                    assertFalse(scheme.Check(h2, r1_p, pp, pk, L1, m1), "not L1");
                }
            }
        }

    }

    @DisplayName("test paper 《Key exposure free chameleon hash schemes based on discrete logarithm problem》")
    @Nested
    class KeyExposureFreeChameleonHashSchemesBasedOnDiscreteLogarithmProblemTest {
        @DisplayName("test CH_KEF_DLP_LLA_2012")
        @Nested
        class CH_KEF_DLP_LLA_2012_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.PublicParam PP = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.PublicParam(curve, group);
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.LabelManager LM = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.LabelManager(PP);
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC scheme = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.PublicKey pk = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.PublicKey();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.SecretKey sk = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.SecretKey();
                scheme.KeyGen(pk, sk, PP, LM);
                Element m1 = PP.GP.GetZrElement();
                Element m2 = PP.GP.GetZrElement();
                Element m3 = PP.GP.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");
                assertFalse(m1.isEqual(m3), "m1 != m3");
                assertFalse(m2.isEqual(m3), "m2 != m3");
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Label L1 = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Label();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Label L2 = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Label();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.HashValue h1 = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.HashValue();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.HashValue h2 = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.HashValue();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness r1 = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness r2 = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness r1_p = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness();
                scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness r1_pp = new scheme.CH.CH_KEF_DLP_LLA_2012.PBC.Randomness();
                scheme.Hash(h1, r1, L1, PP, LM, pk, m1);
                scheme.Hash(h2, r2, L2, PP, LM, pk, m2);
                assertTrue(scheme.Check(h1, r1, PP, pk, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, PP, pk, L2, m1), "not H(L2, m1)");

                assertTrue(scheme.Check(h2, r2, PP, pk, L2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, PP, pk, L1, m2), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, PP, pk, L2, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, PP, pk, L1, m1), "not H(m2)");

                scheme.UForge(r1_p, h1, r1, L1, PP, pk, sk, m1, m3);
                assertTrue(scheme.Check(h1, r1_p, PP, pk, L1, m3), "Adapt(m3) valid");

                scheme.UForge(r1_p, h1, r1, L1, PP, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, PP, pk, L1, m2), "Adapt(m2) valid");

                scheme.IForge(r1_pp, r1, r1_p, m1, m2, m3);
                assertTrue(scheme.Check(h1, r1_pp, PP, pk, L1, m3), "Adapt(m3) valid");
            }

            @SuppressWarnings({"LoopConditionNotUpdatedInsideLoop", "ConstantValue", "unused"})
            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
//            @EnumSource(MCL.class)
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                do {
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.PublicParam PP = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.PublicParam();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.LabelManager LM = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.LabelManager(PP);
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1 scheme = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.PublicKey pk = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.PublicKey();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.SecretKey sk = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.SecretKey();
                    scheme.KeyGen(pk, sk, PP, LM);
                    Fr m1 = new Fr();
                    PP.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    PP.GP.GetZrElement(m2);
                    Fr m3 = new Fr();
                    PP.GP.GetZrElement(m3);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    assertFalse(m1.equals(m3), "m1 != m3");
                    assertFalse(m2.equals(m3), "m2 != m3");
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.Label L1 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.Label();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.Label L2 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.Label();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.HashValue h1 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.HashValue();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.HashValue h2 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.HashValue();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.Randomness r1 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.Randomness();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.Randomness r2 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.Randomness();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.Randomness r1_p = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.Randomness();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.Randomness r1_pp = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G1.Randomness();

                    System.out.println("\n\n12312415124");
                    scheme.Hash(h1, r1, L1, PP, LM, pk, m1);

                    assertTrue(scheme.Check(h1, r1, PP, pk, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, PP, pk, L2, m1), "not H(L2, m1)");

                    scheme.Hash(h2, r2, L2, PP, LM, pk, m2);
                    assertTrue(scheme.Check(h2, r2, PP, pk, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, PP, pk, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, PP, pk, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, PP, pk, L1, m1), "not H(m2)");

                    scheme.UForge(r1_p, h1, r1, L1, PP, pk, sk, m1, m3);
                    assertTrue(scheme.Check(h1, r1_p, PP, pk, L1, m3), "Adapt(m3) valid");

                    scheme.UForge(r1_p, h1, r1, L1, PP, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, PP, pk, L1, m2), "Adapt(m2) valid");

                    scheme.IForge(r1_pp, r1, r1_p, m1, m2, m3);
                    assertTrue(scheme.Check(h1, r1_pp, PP, pk, L1, m3), "Adapt(m3) valid");
                    System.out.println();
                } while(curve == MCL.SECP256K1);

                if(curve != MCL.SECP256K1) {
                    // BadCaseTest#MCL_Bad_Case#Case1
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.PublicParam PP = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.PublicParam();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.LabelManager LM = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.LabelManager(PP);
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2 scheme = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.PublicKey pk = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.PublicKey();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.SecretKey sk = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.SecretKey();
                    scheme.KeyGen(pk, sk, PP, LM);
                    Fr m1 = new Fr();
                    PP.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    PP.GP.GetZrElement(m2);
                    Fr m3 = new Fr();
                    PP.GP.GetZrElement(m3);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    assertFalse(m1.equals(m3), "m1 != m3");
                    assertFalse(m2.equals(m3), "m2 != m3");
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.Label L1 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.Label();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.Label L2 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.Label();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.HashValue h1 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.HashValue();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.HashValue h2 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.HashValue();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.Randomness r1 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.Randomness();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.Randomness r2 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.Randomness();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.Randomness r1_p = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.Randomness();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.Randomness r1_pp = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_G2.Randomness();
                    scheme.Hash(h1, r1, L1, PP, LM, pk, m1);
                    assertTrue(scheme.Check(h1, r1, PP, pk, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, PP, pk, L2, m1), "not H(L2, m1)");

                    scheme.Hash(h2, r2, L2, PP, LM, pk, m2);
                    assertTrue(scheme.Check(h2, r2, PP, pk, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, PP, pk, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, PP, pk, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, PP, pk, L1, m1), "not H(m2)");

                    scheme.UForge(r1_p, h1, r1, L1, PP, pk, sk, m1, m3);
                    assertTrue(scheme.Check(h1, r1_p, PP, pk, L1, m3), "Adapt(m3) valid");

                    scheme.UForge(r1_p, h1, r1, L1, PP, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, PP, pk, L1, m2), "Adapt(m2) valid");

                    scheme.IForge(r1_pp, r1, r1_p, m1, m2, m3);
                    assertTrue(scheme.Check(h1, r1_pp, PP, pk, L1, m3), "Adapt(m3) valid");
                }{
                    // BadCaseTest#MCL_Bad_Case#Case1
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.PublicParam PP = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.PublicParam();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.LabelManager LM = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.LabelManager(PP);
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT scheme = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.PublicKey pk = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.PublicKey();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.SecretKey sk = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.SecretKey();
                    scheme.KeyGen(pk, sk, PP, LM);
                    Fr m1 = new Fr();
                    PP.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    PP.GP.GetZrElement(m2);
                    Fr m3 = new Fr();
                    PP.GP.GetZrElement(m3);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    assertFalse(m1.equals(m3), "m1 != m3");
                    assertFalse(m2.equals(m3), "m2 != m3");
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.Label L1 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.Label();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.Label L2 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.Label();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.HashValue h1 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.HashValue();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.HashValue h2 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.HashValue();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.Randomness r1 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.Randomness();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.Randomness r2 = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.Randomness();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.Randomness r1_p = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.Randomness();
                    scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.Randomness r1_pp = new scheme.CH.CH_KEF_DLP_LLA_2012.MCL_GT.Randomness();
                    scheme.Hash(h1, r1, L1, PP, LM, pk, m1);
                    assertTrue(scheme.Check(h1, r1, PP, pk, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, PP, pk, L2, m1), "not H(L2, m1)");

                    scheme.Hash(h2, r2, L2, PP, LM, pk, m2);
                    assertTrue(scheme.Check(h2, r2, PP, pk, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, PP, pk, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, PP, pk, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, PP, pk, L1, m1), "not H(m2)");

                    scheme.UForge(r1_p, h1, r1, L1, PP, pk, sk, m1, m3);
                    assertTrue(scheme.Check(h1, r1_p, PP, pk, L1, m3), "Adapt(m3) valid");

                    scheme.UForge(r1_p, h1, r1, L1, PP, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, PP, pk, L1, m2), "Adapt(m2) valid");

                    scheme.IForge(r1_pp, r1, r1_p, m1, m2, m3);
                    assertTrue(scheme.Check(h1, r1_pp, PP, pk, L1, m3), "Adapt(m3) valid");
                }
            }
        }
    }

    @DisplayName("test paper 《Chameleon-Hashes with Ephemeral Trapdoors And Applications to Invisible Sanitizable Signatures》")
    @Nested
    class ChameleonHashesWithEphemeralTrapdoorsAndApplicationsToInvisibleSanitizableSignaturesTest {
        @DisplayName("test CH_ET_BC_CDK_2017")
        @Nested
        class CH_ET_BC_CDK_2017_Test {
            @DisplayName("test Native impl")
            @ParameterizedTest(name = "test lambda = {0}")
            @ValueSource(ints = {256, 512, 1024, 2048})
            void NativeTest(int lambda) {
                scheme.CH.CH_ET_BC_CDK_2017.Native scheme = new scheme.CH.CH_ET_BC_CDK_2017.Native(lambda);
                scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey pk = new scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey();
                scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
                scheme.KeyGen(pk, sk);
                String m1 = "WCjrCK";
                String m2 = "123";
                scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue h1 = new scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue();
                scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue h2 = new scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue();
                scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness r1 = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
                scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness r1_p = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
                scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness r2 = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
                scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd1 = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
                scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd2 = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
                scheme.Hash(h1, r1, etd1, pk, m1);
                assertTrue(scheme.Check(h1, r1, pk, m1), "H(m1) valid");
                scheme.Hash(h2, r2, etd2, pk, m2);
                assertTrue(scheme.Check(h2, r2, pk, m2), "H(m2) valid");

                assertFalse(scheme.Check(h1, r1, pk, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, r1, etd1, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, m2), "adapt m2 valid");
                assertFalse(scheme.Check(h1, r1_p, pk, m1), "not adapt m1");
            }
        }

        @DisplayName("test CH_ET_KOG_CDK_2017")
        @Nested
        class CH_ET_KOG_CDK_2017_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.PublicParam pp = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.PublicParam(curve, group, 1024);
                scheme.CH.CH_ET_KOG_CDK_2017.PBC scheme = new scheme.CH.CH_ET_KOG_CDK_2017.PBC();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.PublicKey pk = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.PublicKey();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.SecretKey sk = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.SecretKey();
                scheme.KeyGen(pk, sk, pp);
                Element m1 = pp.GP.GetZrElement();
                Element m2 = pp.GP.GetZrElement();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.HashValue h1 = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.HashValue();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.HashValue h2 = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.HashValue();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.Randomness r1 = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.Randomness();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.Randomness r1_p = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.Randomness();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.Randomness r2 = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.Randomness();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.ETrapdoor etd1 = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.ETrapdoor();
                scheme.CH.CH_ET_KOG_CDK_2017.PBC.ETrapdoor etd2 = new scheme.CH.CH_ET_KOG_CDK_2017.PBC.ETrapdoor();
                scheme.Hash(h1, r1, etd1, pp, pk, m1);
                assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                scheme.Hash(h2, r2, etd2, pp, pk, m2);
                assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");

                assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, r1, etd1, pp, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "adapt m2 valid");
                assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not adapt m1");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.PublicParam pp = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.PublicParam(1024);
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1 scheme = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.PublicKey pk = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.PublicKey();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.SecretKey sk = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.HashValue h1 = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.HashValue();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.HashValue h2 = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.HashValue();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.Randomness r1 = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.Randomness();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.Randomness r1_p = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.Randomness();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.Randomness r2 = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.Randomness();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.ETrapdoor etd1 = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.ETrapdoor();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.ETrapdoor etd2 = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G1.ETrapdoor();
                    scheme.Hash(h1, r1, etd1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    scheme.Hash(h2, r2, etd2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");

                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, etd1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "adapt m2 valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not adapt m1");
                }
                {
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.PublicParam pp = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.PublicParam(1024);
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2 scheme = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.PublicKey pk = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.PublicKey();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.SecretKey sk = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.HashValue h1 = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.HashValue();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.HashValue h2 = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.HashValue();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.Randomness r1 = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.Randomness();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.Randomness r1_p = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.Randomness();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.Randomness r2 = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.Randomness();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.ETrapdoor etd1 = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.ETrapdoor();
                    scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.ETrapdoor etd2 = new scheme.CH.CH_ET_KOG_CDK_2017.MCL_G2.ETrapdoor();
                    scheme.Hash(h1, r1, etd1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    scheme.Hash(h2, r2, etd2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");

                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, etd1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "adapt m2 valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not adapt m1");
                }
            }
        }

        @DisplayName("test CH_CDK_2017")
        @Nested
        class CH_CDK_2017_Test {
            @DisplayName("test Native impl")
            @ParameterizedTest(name = "test lambda = {0}")
            @ValueSource(ints = {256, 512, 1024, 2048})
            void NativeTest(int lambda) {
                Random rand = new Random();
                scheme.CH.CH_CDK_2017.Native scheme = new scheme.CH.CH_CDK_2017.Native(lambda);
                scheme.CH.CH_CDK_2017.Native.PublicKey pk = new scheme.CH.CH_CDK_2017.Native.PublicKey();
                scheme.CH.CH_CDK_2017.Native.SecretKey sk = new scheme.CH.CH_CDK_2017.Native.SecretKey();
                scheme.KeyGen(pk, sk);
                BigInteger m1 = new BigInteger(lambda, rand);
                BigInteger m2 = new BigInteger(lambda, rand);
                BigInteger l1 = new BigInteger(lambda, rand);
                BigInteger l2 = new BigInteger(lambda, rand);
                scheme.CH.CH_CDK_2017.Native.HashValue h1 = new scheme.CH.CH_CDK_2017.Native.HashValue();
                scheme.CH.CH_CDK_2017.Native.HashValue h2 = new scheme.CH.CH_CDK_2017.Native.HashValue();
                scheme.CH.CH_CDK_2017.Native.Randomness r1 = new scheme.CH.CH_CDK_2017.Native.Randomness();
                scheme.CH.CH_CDK_2017.Native.Randomness r1_p = new scheme.CH.CH_CDK_2017.Native.Randomness();
                scheme.CH.CH_CDK_2017.Native.Randomness r2 = new scheme.CH.CH_CDK_2017.Native.Randomness();
                scheme.Hash(h1, r1, pk, l1, m1);
                assertTrue(scheme.Check(h1, r1, pk, l1, m1), "H(l1, m1) valid");
                assertFalse(scheme.Check(h1, r1, pk, l2, m1), "not H(l2, m1)");

                scheme.Hash(h2, r2, pk, l2, m2);
                assertTrue(scheme.Check(h2, r2, pk, l2, m2), "H(l2, m2) valid");
                assertFalse(scheme.Check(h2, r2, pk, l1, m2), "not H(l1, m2)");

                assertFalse(scheme.Check(h1, r1, pk, l1, m2), "not H(l1, m2)");
                assertFalse(scheme.Check(h2, r2, pk, l2, m1), "not H(l2, m1)");

                scheme.Adapt(r1_p, r1, pk, sk, l1, m1, l2, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, l2, m2), "adapt m2 valid");
                assertFalse(scheme.Check(h1, r1_p, pk, l2, m1), "not adapt m1");
                assertFalse(scheme.Check(h1, r1_p, pk, l1, m2), "not adapt l1");
            }
        }

        @DisplayName("test MCH_CDK_2017")
        @Nested
        class MCH_CDK_2017_Test {
            @DisplayName("test Native impl")
            @ParameterizedTest(name = "test lambda = {0}")
            @ValueSource(ints = {256, 512, 1024, 2048})
            void NativeTest(int lambda) {
                scheme.CH.MCH_CDK_2017.Native scheme = new scheme.CH.MCH_CDK_2017.Native(lambda);
                scheme.CH.MCH_CDK_2017.Native.PublicKey pk = new scheme.CH.MCH_CDK_2017.Native.PublicKey();
                scheme.CH.MCH_CDK_2017.Native.SecretKey sk = new scheme.CH.MCH_CDK_2017.Native.SecretKey();
                scheme.KeyGen(pk, sk);
                String m1 = "WCjrCK";
                String m2 = "123";
                scheme.CH.MCH_CDK_2017.Native.HashValue h1 = new scheme.CH.MCH_CDK_2017.Native.HashValue();
                scheme.CH.MCH_CDK_2017.Native.HashValue h2 = new scheme.CH.MCH_CDK_2017.Native.HashValue();
                scheme.CH.MCH_CDK_2017.Native.Randomness r1 = new scheme.CH.MCH_CDK_2017.Native.Randomness();
                scheme.CH.MCH_CDK_2017.Native.Randomness r1_p = new scheme.CH.MCH_CDK_2017.Native.Randomness();
                scheme.CH.MCH_CDK_2017.Native.Randomness r2 = new scheme.CH.MCH_CDK_2017.Native.Randomness();
                scheme.Hash(h1, r1, pk, m1);
                assertTrue(scheme.Check(h1, r1, pk, m1), "H(m1) valid");
                scheme.Hash(h2, r2, pk, m2);
                assertTrue(scheme.Check(h2, r2, pk, m2), "H(m2) valid");

                assertFalse(scheme.Check(h1, r1, pk, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, r1, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, m2), "adapt m2 valid");
                assertFalse(scheme.Check(h1, r1_p, pk, m1), "not adapt m1");
            }
        }

        @DisplayName("test CHET_RSA_CDK_2017")
        @Nested
        class CHET_RSA_CDK_2017_Test {
            @DisplayName("test Native impl")
            @ParameterizedTest(name = "test lambda = {0}")
            @ValueSource(ints = {128, 256, 512})
            void NativeTest(int lambda) {
                Random rand = new Random();
                scheme.CH.CHET_RSA_CDK_2017.Native scheme = new scheme.CH.CHET_RSA_CDK_2017.Native(lambda);
                scheme.CH.CHET_RSA_CDK_2017.Native.PublicKey pk = new scheme.CH.CHET_RSA_CDK_2017.Native.PublicKey();
                scheme.CH.CHET_RSA_CDK_2017.Native.SecretKey sk = new scheme.CH.CHET_RSA_CDK_2017.Native.SecretKey();
                scheme.KeyGen(pk, sk);
                BigInteger m1 = new BigInteger(lambda, rand);
                BigInteger m2 = new BigInteger(lambda, rand);
                assertTrue(m1.compareTo(m2) != 0, "m1 != m2");
                scheme.CH.CHET_RSA_CDK_2017.Native.HashValue h1 = new scheme.CH.CHET_RSA_CDK_2017.Native.HashValue();
                scheme.CH.CHET_RSA_CDK_2017.Native.HashValue h2 = new scheme.CH.CHET_RSA_CDK_2017.Native.HashValue();
                scheme.CH.CHET_RSA_CDK_2017.Native.Randomness r1 = new scheme.CH.CHET_RSA_CDK_2017.Native.Randomness();
                scheme.CH.CHET_RSA_CDK_2017.Native.Randomness r1_p = new scheme.CH.CHET_RSA_CDK_2017.Native.Randomness();
                scheme.CH.CHET_RSA_CDK_2017.Native.Randomness r2 = new scheme.CH.CHET_RSA_CDK_2017.Native.Randomness();
                scheme.CH.CHET_RSA_CDK_2017.Native.ETrapdoor etd1 = new scheme.CH.CHET_RSA_CDK_2017.Native.ETrapdoor();
                scheme.CH.CHET_RSA_CDK_2017.Native.ETrapdoor etd2 = new scheme.CH.CHET_RSA_CDK_2017.Native.ETrapdoor();
                scheme.Hash(h1, r1, etd1, pk, m1);
                assertTrue(scheme.Check(h1, r1, pk, m1), "H(m1) valid");
                scheme.Hash(h2, r2, etd2, pk, m2);
                assertTrue(scheme.Check(h2, r2, pk, m2), "H(m2) valid");

                assertFalse(scheme.Check(h1, r1, pk, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, r1, etd1, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pk, m2), "adapt m2 valid");
                assertFalse(scheme.Check(h1, r1_p, pk, m1), "not adapt m1");
            }
        }
    }

    @DisplayName("test paper 《Chameleon Hashing without Key Exposure》")
    @Nested
    class ChameleonHashingWithoutKeyExposureTest {
        @DisplayName("test CH_KEF_CZK_2004")
        @Nested
        class CH_KEF_CZK_2004_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                scheme.CH.CH_KEF_CZK_2004.PBC scheme = new scheme.CH.CH_KEF_CZK_2004.PBC();
                scheme.CH.CH_KEF_CZK_2004.PBC.PublicParam SP = new scheme.CH.CH_KEF_CZK_2004.PBC.PublicParam(curve, group);
                scheme.CH.CH_KEF_CZK_2004.PBC.PublicKey pk = new scheme.CH.CH_KEF_CZK_2004.PBC.PublicKey();
                scheme.CH.CH_KEF_CZK_2004.PBC.SecretKey sk = new scheme.CH.CH_KEF_CZK_2004.PBC.SecretKey();
                scheme.KeyGen(pk, sk, SP);
                Element m1 = SP.GP.GetZrElement();
                Element m2 = SP.GP.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");
                Element L1;
                Element L2;
                L1 = SP.H("S11|R11|T11");
                L2 = SP.H("S22|R22|T22");
                assertFalse(L1.isEqual(L2), "L1 != L2");
                scheme.CH.CH_KEF_CZK_2004.PBC.HashValue h1 = new scheme.CH.CH_KEF_CZK_2004.PBC.HashValue();
                scheme.CH.CH_KEF_CZK_2004.PBC.HashValue h2 = new scheme.CH.CH_KEF_CZK_2004.PBC.HashValue();
                scheme.CH.CH_KEF_CZK_2004.PBC.Randomness r1 = new scheme.CH.CH_KEF_CZK_2004.PBC.Randomness();
                scheme.CH.CH_KEF_CZK_2004.PBC.Randomness r2 = new scheme.CH.CH_KEF_CZK_2004.PBC.Randomness();
                scheme.CH.CH_KEF_CZK_2004.PBC.Randomness r1_p = new scheme.CH.CH_KEF_CZK_2004.PBC.Randomness();
                scheme.Hash(h1, r1, SP, pk, L1, m1);
                assertTrue(scheme.Check(h1, r1, SP, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, SP, L2, m1), "not H(L2, m1)");

                scheme.Hash(h2, r2, SP, pk, L2, m2);
                assertTrue(scheme.Check(h2, r2, SP, L2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, SP, L1, m2), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, SP, L2, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, SP, L1, m1), "not H(m2)");

                scheme.Adapt(r1_p, r1, SP, sk, L1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, SP, L1, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h2, r1_p, SP, L1, m1), "not Adapt(m1)");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    scheme.CH.CH_KEF_CZK_2004.MCL_G1 scheme = new scheme.CH.CH_KEF_CZK_2004.MCL_G1();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G1.PublicParam SP = new scheme.CH.CH_KEF_CZK_2004.MCL_G1.PublicParam();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G1.PublicKey pk = new scheme.CH.CH_KEF_CZK_2004.MCL_G1.PublicKey();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G1.SecretKey sk = new scheme.CH.CH_KEF_CZK_2004.MCL_G1.SecretKey();
                    scheme.KeyGen(pk, sk, SP);
                    Fr m1 = new Fr();
                    SP.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    SP.GP.GetZrElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    G1 L1 = new G1();
                    SP.GP.GetGElement(L1);
                    G1 L2 = new G1();
                    SP.GP.GetGElement(L2);

                    assertFalse(L1.equals(L2), "L1 != L2");
                    scheme.CH.CH_KEF_CZK_2004.MCL_G1.HashValue h1 = new scheme.CH.CH_KEF_CZK_2004.MCL_G1.HashValue();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G1.HashValue h2 = new scheme.CH.CH_KEF_CZK_2004.MCL_G1.HashValue();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G1.Randomness r1 = new scheme.CH.CH_KEF_CZK_2004.MCL_G1.Randomness();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G1.Randomness r2 = new scheme.CH.CH_KEF_CZK_2004.MCL_G1.Randomness();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G1.Randomness r1_p = new scheme.CH.CH_KEF_CZK_2004.MCL_G1.Randomness();
                    scheme.Hash(h1, r1, SP, pk, L1, m1);
                    assertTrue(scheme.Check(h1, r1, SP, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, SP, L2, m1), "not H(L2, m1)");

                    scheme.Hash(h2, r2, SP, pk, L2, m2);
                    assertTrue(scheme.Check(h2, r2, SP, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, SP, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, SP, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, SP, L1, m1), "not H(m2)");

                    scheme.Adapt(r1_p, r1, SP, sk, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, L1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h2, r1_p, SP, L1, m1), "not Adapt(m1)");
                }
                {
                    scheme.CH.CH_KEF_CZK_2004.MCL_G2 scheme = new scheme.CH.CH_KEF_CZK_2004.MCL_G2();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G2.PublicParam SP = new scheme.CH.CH_KEF_CZK_2004.MCL_G2.PublicParam();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G2.PublicKey pk = new scheme.CH.CH_KEF_CZK_2004.MCL_G2.PublicKey();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G2.SecretKey sk = new scheme.CH.CH_KEF_CZK_2004.MCL_G2.SecretKey();
                    scheme.KeyGen(pk, sk, SP);
                    Fr m1 = new Fr();
                    SP.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    SP.GP.GetZrElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    G2 L1 = new G2();
                    SP.GP.GetGElement(L1);
                    G2 L2 = new G2();
                    SP.GP.GetGElement(L2);

                    assertFalse(L1.equals(L2), "L1 != L2");
                    scheme.CH.CH_KEF_CZK_2004.MCL_G2.HashValue h1 = new scheme.CH.CH_KEF_CZK_2004.MCL_G2.HashValue();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G2.HashValue h2 = new scheme.CH.CH_KEF_CZK_2004.MCL_G2.HashValue();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G2.Randomness r1 = new scheme.CH.CH_KEF_CZK_2004.MCL_G2.Randomness();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G2.Randomness r2 = new scheme.CH.CH_KEF_CZK_2004.MCL_G2.Randomness();
                    scheme.CH.CH_KEF_CZK_2004.MCL_G2.Randomness r1_p = new scheme.CH.CH_KEF_CZK_2004.MCL_G2.Randomness();
                    scheme.Hash(h1, r1, SP, pk, L1, m1);
                    assertTrue(scheme.Check(h1, r1, SP, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, SP, L2, m1), "not H(L2, m1)");

                    scheme.Hash(h2, r2, SP, pk, L2, m2);
                    assertTrue(scheme.Check(h2, r2, SP, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, SP, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, SP, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, SP, L1, m1), "not H(m2)");

                    scheme.Adapt(r1_p, r1, SP, sk, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, L1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h2, r1_p, SP, L1, m1), "not Adapt(m1)");
                }
                {
                    scheme.CH.CH_KEF_CZK_2004.MCL_GT scheme = new scheme.CH.CH_KEF_CZK_2004.MCL_GT();
                    scheme.CH.CH_KEF_CZK_2004.MCL_GT.PublicParam SP = new scheme.CH.CH_KEF_CZK_2004.MCL_GT.PublicParam();
                    scheme.CH.CH_KEF_CZK_2004.MCL_GT.PublicKey pk = new scheme.CH.CH_KEF_CZK_2004.MCL_GT.PublicKey();
                    scheme.CH.CH_KEF_CZK_2004.MCL_GT.SecretKey sk = new scheme.CH.CH_KEF_CZK_2004.MCL_GT.SecretKey();
                    scheme.KeyGen(pk, sk, SP);
                    Fr m1 = new Fr();
                    SP.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    SP.GP.GetZrElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    GT L1 = new GT();
                    SP.GP.GetGElement(L1);
                    GT L2 = new GT();
                    SP.GP.GetGElement(L2);

                    assertFalse(L1.equals(L2), "L1 != L2");
                    scheme.CH.CH_KEF_CZK_2004.MCL_GT.HashValue h1 = new scheme.CH.CH_KEF_CZK_2004.MCL_GT.HashValue();
                    scheme.CH.CH_KEF_CZK_2004.MCL_GT.HashValue h2 = new scheme.CH.CH_KEF_CZK_2004.MCL_GT.HashValue();
                    scheme.CH.CH_KEF_CZK_2004.MCL_GT.Randomness r1 = new scheme.CH.CH_KEF_CZK_2004.MCL_GT.Randomness();
                    scheme.CH.CH_KEF_CZK_2004.MCL_GT.Randomness r2 = new scheme.CH.CH_KEF_CZK_2004.MCL_GT.Randomness();
                    scheme.CH.CH_KEF_CZK_2004.MCL_GT.Randomness r1_p = new scheme.CH.CH_KEF_CZK_2004.MCL_GT.Randomness();
                    scheme.Hash(h1, r1, SP, pk, L1, m1);
                    assertTrue(scheme.Check(h1, r1, SP, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, SP, L2, m1), "not H(L2, m1)");

                    scheme.Hash(h2, r2, SP, pk, L2, m2);
                    assertTrue(scheme.Check(h2, r2, SP, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, SP, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, SP, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, SP, L1, m1), "not H(m2)");

                    scheme.Adapt(r1_p, r1, SP, sk, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, L1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h2, r1_p, SP, L1, m1), "not Adapt(m1)");
                }
            }
        }
    }

    @DisplayName("test paper 《Discrete logarithm based chameleon hashing and signatures withoutkey exposure》")
    @Nested
    class DiscreteLogarithmBasedChameleonHashingAndSignaturesWithoutkeyExposureTest {
        @DisplayName("test CH_KEF_DL_CZT_2011")
        @Nested
        class CH_KEF_DL_CZT_2011_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                scheme.CH.CH_KEF_DL_CZT_2011.PBC scheme = new scheme.CH.CH_KEF_DL_CZT_2011.PBC();
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.PublicParam SP = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.PublicParam(curve, group);
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.PublicKey pk = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.PublicKey();
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.SecretKey sk = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.SecretKey();
                scheme.KeyGen(pk, sk, SP);
                Element m1 = SP.GP.GetZrElement();
                Element m2 = SP.GP.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");
                Element L1 = SP.GP.GetZrElement();
                Element L2 = SP.GP.GetZrElement();
                assertFalse(L1.isEqual(L2), "L1 != L2");
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.HashValue h1 = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.HashValue();
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.HashValue h2 = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.HashValue();
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.Randomness r1 = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.Randomness();
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.Randomness r2 = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.Randomness();
                scheme.CH.CH_KEF_DL_CZT_2011.PBC.Randomness r1_p = new scheme.CH.CH_KEF_DL_CZT_2011.PBC.Randomness();
                scheme.Hash(h1, r1, SP, pk, L1, m1);
                assertTrue(scheme.Check(h1, r1, SP, pk, L1, m1), "H(L1, m1) valid");
                assertFalse(scheme.Check(h1, r1, SP, pk, L2, m1), "not H(L2, m1)");

                scheme.Hash(h2, r2, SP, pk, L2, m2);
                assertTrue(scheme.Check(h2, r2, SP, pk, L2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, SP, pk, L1, m2), "not H(L1, m2)");

                assertFalse(scheme.Check(h1, r1, SP, pk, L2, m2), "not H(m1)");
                assertFalse(scheme.Check(h2, r2, SP, pk, L1, m1), "not H(m2)");

                scheme.Adapt(r1_p, r1, SP, pk, sk, L1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, SP, pk, L1, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h2, r1_p, SP, pk, L1, m1), "not Adapt(m1)");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1 scheme = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.PublicParam SP = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.PublicParam();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.PublicKey pk = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.PublicKey();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.SecretKey sk = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.SecretKey();
                    scheme.KeyGen(pk, sk, SP);
                    Fr m1 = new Fr();
                    SP.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    SP.GP.GetZrElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    Fr L1 = new Fr();
                    SP.GP.GetZrElement(L1);
                    Fr L2 = new Fr();
                    SP.GP.GetZrElement(L2);
                    assertFalse(L1.equals(L2), "L1 != L2");
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.HashValue h1 = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.HashValue();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.HashValue h2 = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.HashValue();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.Randomness r1 = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.Randomness();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.Randomness r2 = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.Randomness();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.Randomness r1_p = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G1.Randomness();
                    scheme.Hash(h1, r1, SP, pk, L1, m1);
                    assertTrue(scheme.Check(h1, r1, SP, pk, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, SP, pk, L2, m1), "not H(L2, m1)");

                    scheme.Hash(h2, r2, SP, pk, L2, m2);
                    assertTrue(scheme.Check(h2, r2, SP, pk, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, SP, pk, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, SP, pk, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, SP, pk, L1, m1), "not H(m2)");

                    scheme.Adapt(r1_p, r1, SP, pk, sk, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, pk, L1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h2, r1_p, SP, pk, L1, m1), "not Adapt(m1)");
                }
                {
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2 scheme = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.PublicParam SP = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.PublicParam();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.PublicKey pk = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.PublicKey();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.SecretKey sk = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.SecretKey();
                    scheme.KeyGen(pk, sk, SP);
                    Fr m1 = new Fr();
                    SP.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    SP.GP.GetZrElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    Fr L1 = new Fr();
                    SP.GP.GetZrElement(L1);
                    Fr L2 = new Fr();
                    SP.GP.GetZrElement(L2);
                    assertFalse(L1.equals(L2), "L1 != L2");
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.HashValue h1 = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.HashValue();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.HashValue h2 = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.HashValue();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.Randomness r1 = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.Randomness();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.Randomness r2 = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.Randomness();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.Randomness r1_p = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_G2.Randomness();
                    scheme.Hash(h1, r1, SP, pk, L1, m1);
                    assertTrue(scheme.Check(h1, r1, SP, pk, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, SP, pk, L2, m1), "not H(L2, m1)");

                    scheme.Hash(h2, r2, SP, pk, L2, m2);
                    assertTrue(scheme.Check(h2, r2, SP, pk, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, SP, pk, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, SP, pk, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, SP, pk, L1, m1), "not H(m2)");

                    scheme.Adapt(r1_p, r1, SP, pk, sk, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, pk, L1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h2, r1_p, SP, pk, L1, m1), "not Adapt(m1)");
                }
                {
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT scheme = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.PublicParam SP = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.PublicParam();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.PublicKey pk = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.PublicKey();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.SecretKey sk = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.SecretKey();
                    scheme.KeyGen(pk, sk, SP);
                    Fr m1 = new Fr();
                    SP.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    SP.GP.GetZrElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");
                    Fr L1 = new Fr();
                    SP.GP.GetZrElement(L1);
                    Fr L2 = new Fr();
                    SP.GP.GetZrElement(L2);
                    assertFalse(L1.equals(L2), "L1 != L2");
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.HashValue h1 = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.HashValue();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.HashValue h2 = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.HashValue();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.Randomness r1 = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.Randomness();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.Randomness r2 = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.Randomness();
                    scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.Randomness r1_p = new scheme.CH.CH_KEF_DL_CZT_2011.MCL_GT.Randomness();
                    scheme.Hash(h1, r1, SP, pk, L1, m1);
                    assertTrue(scheme.Check(h1, r1, SP, pk, L1, m1), "H(L1, m1) valid");
                    assertFalse(scheme.Check(h1, r1, SP, pk, L2, m1), "not H(L2, m1)");

                    scheme.Hash(h2, r2, SP, pk, L2, m2);
                    assertTrue(scheme.Check(h2, r2, SP, pk, L2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, SP, pk, L1, m2), "not H(L1, m2)");

                    assertFalse(scheme.Check(h1, r1, SP, pk, L2, m2), "not H(m1)");
                    assertFalse(scheme.Check(h2, r2, SP, pk, L1, m1), "not H(m2)");

                    scheme.Adapt(r1_p, r1, SP, pk, sk, L1, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, pk, L1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h2, r1_p, SP, pk, L1, m1), "not Adapt(m1)");
                }
            }
        }
    }

    @DisplayName("test paper 《Fully Collision-Resistant Chameleon-Hashes from Simpler and Post-Quantum Assumptions》")
    @Nested
    class FullyCollisionResistantChameleonHashesFromSimplerAndPostQuantumAssumptionsTest {
        @DisplayName("test FCR_CH_PreQA_DKS_2020")
        @Nested
        class FCR_CH_PreQA_DKS_2020_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                scheme.CH.FCR_CH_PreQA_DKS_2020.PBC scheme = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC();
                scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicParam pp = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicParam(curve, group);
                scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicKey pk = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.PublicKey();
                scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.SecretKey sk = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.SecretKey();
                scheme.KeyGen(pk, sk, pp);
                Element m1 = pp.GP.GetZrElement();
                Element m2 = pp.GP.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");

                scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.HashValue h1 = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.HashValue();
                scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.HashValue h2 = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.HashValue();
                scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.Randomness r1 = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.Randomness();
                scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.Randomness r2 = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.Randomness();
                scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.Randomness r1_p = new scheme.CH.FCR_CH_PreQA_DKS_2020.PBC.Randomness();
                scheme.Hash(h1, r1, pp, pk, m1);
                assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                scheme.Hash(h2, r2, pp, pk, m2);
                assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1 scheme = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.PublicParam pp = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.PublicParam();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.PublicKey pk = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.PublicKey();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.SecretKey sk = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.HashValue h1 = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.HashValue();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.HashValue h2 = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.HashValue();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.Randomness r1 = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.Randomness();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.Randomness r2 = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.Randomness();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.Randomness r1_p = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G1.Randomness();
                    scheme.Hash(h1, r1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    scheme.Hash(h2, r2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
                }
                {
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2 scheme = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.PublicParam pp = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.PublicParam();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.PublicKey pk = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.PublicKey();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.SecretKey sk = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.HashValue h1 = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.HashValue();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.HashValue h2 = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.HashValue();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.Randomness r1 = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.Randomness();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.Randomness r2 = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.Randomness();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.Randomness r1_p = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_G2.Randomness();
                    scheme.Hash(h1, r1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    scheme.Hash(h2, r2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
                }
                {
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT scheme = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.PublicParam pp = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.PublicParam();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.PublicKey pk = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.PublicKey();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.SecretKey sk = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.HashValue h1 = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.HashValue();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.HashValue h2 = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.HashValue();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.Randomness r1 = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.Randomness();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.Randomness r2 = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.Randomness();
                    scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.Randomness r1_p = new scheme.CH.FCR_CH_PreQA_DKS_2020.MCL_GT.Randomness();
                    scheme.Hash(h1, r1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    scheme.Hash(h2, r2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
                }
            }
        }
    }

    @DisplayName("test paper 《Bringing Order to Chaos：The Case of Collision-Resistant Chameleon-Hashes》")
    @Nested
    class BringingOrderToChaosTheCaseOfCollisionResistantChameleonHashesTest {
        @DisplayName("test CR_CH_DSS_2020")
        @Nested
        class CR_CH_DSS_2020_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                scheme.CH.CR_CH_DSS_2020.PBC scheme = new scheme.CH.CR_CH_DSS_2020.PBC();
                scheme.CH.CR_CH_DSS_2020.PBC.PublicParam pp = new scheme.CH.CR_CH_DSS_2020.PBC.PublicParam(curve, group);
                scheme.CH.CR_CH_DSS_2020.PBC.PublicKey pk = new scheme.CH.CR_CH_DSS_2020.PBC.PublicKey();
                scheme.CH.CR_CH_DSS_2020.PBC.SecretKey sk = new scheme.CH.CR_CH_DSS_2020.PBC.SecretKey();
                scheme.KeyGen(pk, sk, pp);
                Element m1 = pp.GP.GetGElement();
                Element m2 = pp.GP.GetGElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");

                scheme.CH.CR_CH_DSS_2020.PBC.HashValue h1 = new scheme.CH.CR_CH_DSS_2020.PBC.HashValue();
                scheme.CH.CR_CH_DSS_2020.PBC.HashValue h2 = new scheme.CH.CR_CH_DSS_2020.PBC.HashValue();
                scheme.CH.CR_CH_DSS_2020.PBC.Randomness r1 = new scheme.CH.CR_CH_DSS_2020.PBC.Randomness();
                scheme.CH.CR_CH_DSS_2020.PBC.Randomness r2 = new scheme.CH.CR_CH_DSS_2020.PBC.Randomness();
                scheme.CH.CR_CH_DSS_2020.PBC.Randomness r1_p = new scheme.CH.CR_CH_DSS_2020.PBC.Randomness();
                scheme.Hash(h1, r1, pp, pk, m1);
                assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                scheme.Hash(h2, r2, pp, pk, m2);
                assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    scheme.CH.CR_CH_DSS_2020.MCL_G1 scheme = new scheme.CH.CR_CH_DSS_2020.MCL_G1();
                    scheme.CH.CR_CH_DSS_2020.MCL_G1.PublicParam pp = new scheme.CH.CR_CH_DSS_2020.MCL_G1.PublicParam();
                    scheme.CH.CR_CH_DSS_2020.MCL_G1.PublicKey pk = new scheme.CH.CR_CH_DSS_2020.MCL_G1.PublicKey();
                    scheme.CH.CR_CH_DSS_2020.MCL_G1.SecretKey sk = new scheme.CH.CR_CH_DSS_2020.MCL_G1.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    G1 m1 = new G1();
                    pp.GP.GetGElement(m1);
                    G1 m2 = new G1();
                    pp.GP.GetGElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    scheme.CH.CR_CH_DSS_2020.MCL_G1.HashValue h1 = new scheme.CH.CR_CH_DSS_2020.MCL_G1.HashValue();
                    scheme.CH.CR_CH_DSS_2020.MCL_G1.HashValue h2 = new scheme.CH.CR_CH_DSS_2020.MCL_G1.HashValue();
                    scheme.CH.CR_CH_DSS_2020.MCL_G1.Randomness r1 = new scheme.CH.CR_CH_DSS_2020.MCL_G1.Randomness();
                    scheme.CH.CR_CH_DSS_2020.MCL_G1.Randomness r2 = new scheme.CH.CR_CH_DSS_2020.MCL_G1.Randomness();
                    scheme.CH.CR_CH_DSS_2020.MCL_G1.Randomness r1_p = new scheme.CH.CR_CH_DSS_2020.MCL_G1.Randomness();
                    scheme.Hash(h1, r1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    scheme.Hash(h2, r2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
                }
                {
                    scheme.CH.CR_CH_DSS_2020.MCL_G2 scheme = new scheme.CH.CR_CH_DSS_2020.MCL_G2();
                    scheme.CH.CR_CH_DSS_2020.MCL_G2.PublicParam pp = new scheme.CH.CR_CH_DSS_2020.MCL_G2.PublicParam();
                    scheme.CH.CR_CH_DSS_2020.MCL_G2.PublicKey pk = new scheme.CH.CR_CH_DSS_2020.MCL_G2.PublicKey();
                    scheme.CH.CR_CH_DSS_2020.MCL_G2.SecretKey sk = new scheme.CH.CR_CH_DSS_2020.MCL_G2.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    G2 m1 = new G2();
                    pp.GP.GetGElement(m1);
                    G2 m2 = new G2();
                    pp.GP.GetGElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    scheme.CH.CR_CH_DSS_2020.MCL_G2.HashValue h1 = new scheme.CH.CR_CH_DSS_2020.MCL_G2.HashValue();
                    scheme.CH.CR_CH_DSS_2020.MCL_G2.HashValue h2 = new scheme.CH.CR_CH_DSS_2020.MCL_G2.HashValue();
                    scheme.CH.CR_CH_DSS_2020.MCL_G2.Randomness r1 = new scheme.CH.CR_CH_DSS_2020.MCL_G2.Randomness();
                    scheme.CH.CR_CH_DSS_2020.MCL_G2.Randomness r2 = new scheme.CH.CR_CH_DSS_2020.MCL_G2.Randomness();
                    scheme.CH.CR_CH_DSS_2020.MCL_G2.Randomness r1_p = new scheme.CH.CR_CH_DSS_2020.MCL_G2.Randomness();
                    scheme.Hash(h1, r1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    scheme.Hash(h2, r2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
                }
                {
                    scheme.CH.CR_CH_DSS_2020.MCL_GT scheme = new scheme.CH.CR_CH_DSS_2020.MCL_GT();
                    scheme.CH.CR_CH_DSS_2020.MCL_GT.PublicParam pp = new scheme.CH.CR_CH_DSS_2020.MCL_GT.PublicParam();
                    scheme.CH.CR_CH_DSS_2020.MCL_GT.PublicKey pk = new scheme.CH.CR_CH_DSS_2020.MCL_GT.PublicKey();
                    scheme.CH.CR_CH_DSS_2020.MCL_GT.SecretKey sk = new scheme.CH.CR_CH_DSS_2020.MCL_GT.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    GT m1 = new GT();
                    pp.GP.GetGElement(m1);
                    GT m2 = new GT();
                    pp.GP.GetGElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    scheme.CH.CR_CH_DSS_2020.MCL_GT.HashValue h1 = new scheme.CH.CR_CH_DSS_2020.MCL_GT.HashValue();
                    scheme.CH.CR_CH_DSS_2020.MCL_GT.HashValue h2 = new scheme.CH.CR_CH_DSS_2020.MCL_GT.HashValue();
                    scheme.CH.CR_CH_DSS_2020.MCL_GT.Randomness r1 = new scheme.CH.CR_CH_DSS_2020.MCL_GT.Randomness();
                    scheme.CH.CR_CH_DSS_2020.MCL_GT.Randomness r2 = new scheme.CH.CR_CH_DSS_2020.MCL_GT.Randomness();
                    scheme.CH.CR_CH_DSS_2020.MCL_GT.Randomness r1_p = new scheme.CH.CR_CH_DSS_2020.MCL_GT.Randomness();
                    scheme.Hash(h1, r1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    scheme.Hash(h2, r2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
                }
            }
        }
    }

    @DisplayName("test paper 《Reconstructing Chameleon Hash: Full Security and the Multi-Party Setting》")
    @Nested
    class ReconstructingChameleonHashFullSecurityAndTheMultiPartySettingTest {
        @DisplayName("test CH_FS_ECC_CCT_2024")
        @Nested
        class CH_FS_ECC_CCT_2024_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                scheme.CH.CH_FS_ECC_CCT_2024.PBC scheme = new scheme.CH.CH_FS_ECC_CCT_2024.PBC();
                scheme.CH.CH_FS_ECC_CCT_2024.PBC.PublicParam pp = new scheme.CH.CH_FS_ECC_CCT_2024.PBC.PublicParam(curve, group);
                scheme.CH.CH_FS_ECC_CCT_2024.PBC.PublicKey pk = new scheme.CH.CH_FS_ECC_CCT_2024.PBC.PublicKey();
                scheme.CH.CH_FS_ECC_CCT_2024.PBC.SecretKey sk = new scheme.CH.CH_FS_ECC_CCT_2024.PBC.SecretKey();
                scheme.KeyGen(pk, sk, pp);
                Element m1 = pp.GP.GetGElement();
                Element m2 = pp.GP.GetGElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");

                scheme.CH.CH_FS_ECC_CCT_2024.PBC.HashValue h1 = new scheme.CH.CH_FS_ECC_CCT_2024.PBC.HashValue();
                scheme.CH.CH_FS_ECC_CCT_2024.PBC.HashValue h2 = new scheme.CH.CH_FS_ECC_CCT_2024.PBC.HashValue();
                scheme.CH.CH_FS_ECC_CCT_2024.PBC.Randomness r1 = new scheme.CH.CH_FS_ECC_CCT_2024.PBC.Randomness();
                scheme.CH.CH_FS_ECC_CCT_2024.PBC.Randomness r2 = new scheme.CH.CH_FS_ECC_CCT_2024.PBC.Randomness();
                scheme.CH.CH_FS_ECC_CCT_2024.PBC.Randomness r1_p = new scheme.CH.CH_FS_ECC_CCT_2024.PBC.Randomness();
                scheme.Hash(h1, r1, pp, pk, m1);
                assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                scheme.Hash(h2, r2, pp, pk, m2);
                assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0}")
            // BadCaseTest#MCL_Bad_Case#Case2
            @EnumSource(names = {"BN254", "BLS12_381"})
            void MCLTest(MCL curve) {
                Func.MCLInit(curve);
                {
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1 scheme = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.PublicParam pp = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.PublicParam();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.PublicKey pk = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.PublicKey();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.SecretKey sk = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.HashValue h1 = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.HashValue();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.HashValue h2 = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.HashValue();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.Randomness r1 = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.Randomness();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.Randomness r2 = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.Randomness();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.Randomness r1_p = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G1.Randomness();
                    scheme.Hash(h1, r1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    scheme.Hash(h2, r2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
                }
                {
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2 scheme = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.PublicParam pp = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.PublicParam();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.PublicKey pk = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.PublicKey();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.SecretKey sk = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.HashValue h1 = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.HashValue();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.HashValue h2 = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.HashValue();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.Randomness r1 = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.Randomness();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.Randomness r2 = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.Randomness();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.Randomness r1_p = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_G2.Randomness();
                    scheme.Hash(h1, r1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    scheme.Hash(h2, r2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
                }
                {
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT scheme = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.PublicParam pp = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.PublicParam();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.PublicKey pk = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.PublicKey();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.SecretKey sk = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.SecretKey();
                    scheme.KeyGen(pk, sk, pp);
                    Fr m1 = new Fr();
                    pp.GP.GetZrElement(m1);
                    Fr m2 = new Fr();
                    pp.GP.GetZrElement(m2);
                    assertFalse(m1.equals(m2), "m1 != m2");

                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.HashValue h1 = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.HashValue();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.HashValue h2 = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.HashValue();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.Randomness r1 = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.Randomness();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.Randomness r2 = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.Randomness();
                    scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.Randomness r1_p = new scheme.CH.CH_FS_ECC_CCT_2024.MCL_GT.Randomness();
                    scheme.Hash(h1, r1, pp, pk, m1);
                    assertTrue(scheme.Check(h1, r1, pp, pk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pp, pk, m2), "not H(m1)");
                    scheme.Hash(h2, r2, pp, pk, m2);
                    assertTrue(scheme.Check(h2, r2, pp, pk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pp, pk, m1), "not H(m2)");

                    scheme.Adapt(r1_p, h1, r1, pp, pk, sk, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pp, pk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pp, pk, m1), "not Adapt(m1)");
                }
            }
        }
    }

    @DisplayName("test paper 《Redactable Blockchain or Rewriting History in Bitcoin and Friends》")
    @Nested
    class RedactableBlockchainOrRewritingHistoryInBitcoinAndFriendsTest {
        @DisplayName("test CH_AMV_2017")
        @Nested
        class CH_AMV_2017_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} group {1}")
            @MethodSource("CHTest#GetPBCCartesianProduct")
            void JPBCTest(curve.PBC curve, Group group) {
                scheme.CH.CH_AMV_2017.PBC scheme = new scheme.CH.CH_AMV_2017.PBC();
                scheme.CH.CH_AMV_2017.PBC.PublicParam pp = new scheme.CH.CH_AMV_2017.PBC.PublicParam();
                scheme.CH.CH_AMV_2017.PBC.PublicKey pk = new scheme.CH.CH_AMV_2017.PBC.PublicKey();
                scheme.CH.CH_AMV_2017.PBC.SecretKey sk = new scheme.CH.CH_AMV_2017.PBC.SecretKey();
                scheme.SetUp(pp, curve, group);
                scheme.KeyGen(pk, sk, pp);
                Element m1 = pp.GetZrElement();
                Element m2 = pp.GetZrElement();
                assertFalse(m1.isEqual(m2), "m1 != m2");

                scheme.CH.CH_AMV_2017.PBC.HashValue h1 = new scheme.CH.CH_AMV_2017.PBC.HashValue();
                scheme.CH.CH_AMV_2017.PBC.HashValue h2 = new scheme.CH.CH_AMV_2017.PBC.HashValue();
                scheme.CH.CH_AMV_2017.PBC.Randomness r1 = new scheme.CH.CH_AMV_2017.PBC.Randomness();
                scheme.CH.CH_AMV_2017.PBC.Randomness r2 = new scheme.CH.CH_AMV_2017.PBC.Randomness();
                scheme.CH.CH_AMV_2017.PBC.Randomness r1_p = new scheme.CH.CH_AMV_2017.PBC.Randomness();
                scheme.CH.CH_AMV_2017.PBC.EncRandomness er1 = new scheme.CH.CH_AMV_2017.PBC.EncRandomness();
                scheme.CH.CH_AMV_2017.PBC.EncRandomness er2 = new scheme.CH.CH_AMV_2017.PBC.EncRandomness();
                scheme.CH.CH_AMV_2017.PBC.EncRandomness er1_p = new scheme.CH.CH_AMV_2017.PBC.EncRandomness();
                scheme.Hash(h1, er1, r1, pp, pk, m1);
                assertTrue(scheme.Check(h1, er1, pp, pk, m1), "H(m1) valid");
                assertFalse(scheme.Check(h1, er1, pp, pk, m2), "not H(m1)");
                scheme.Hash(h2, er2, r2, pp, pk, m2);
                assertTrue(scheme.Check(h2, er2, pp, pk, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, er2, pp, pk, m1), "not H(m2)");

                scheme.Adapt(er1_p, r1_p, h1, er1, pp, pk, sk, m1, m2);
                assertTrue(scheme.Check(h1, er1_p, pp, pk, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, er1_p, pp, pk, m1), "not Adapt(m1)");
            }
        }
    }
}
