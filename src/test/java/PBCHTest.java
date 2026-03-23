import curve.Group;
import curve.MCL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import utils.BooleanFormulaParser;

import java.util.EnumSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

public class PBCHTest {
    public static Stream<Arguments> GetPBCSymmAuth() {
        return Stream.of(curve.PBC.A, curve.PBC.A1, curve.PBC.E).flatMap(a ->
                Stream.of(16, 32, 64).flatMap(b ->
                        Stream.of(32, 64, 128).flatMap(c -> Stream.of(Arguments.of(a, b, c)))));
    }

    public static Stream<Arguments> GetPBCSymmAuthBigLambda() {
        return Stream.of(curve.PBC.A, curve.PBC.A1, curve.PBC.E).flatMap(a ->
                Stream.of(16, 32, 64).flatMap(b ->
                        Stream.of(256, 512, 1024).flatMap(c -> Stream.of(Arguments.of(a, b, c)))));
    }

    public static Stream<Arguments> GetPBCInvertk() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                Stream.of(256, 512, 1024).flatMap(b ->
                        Stream.of(Arguments.of(a, false, b), Arguments.of(a, true, b))
                )
        );
    }

    public static Stream<Arguments> GetMCLInvertk() {
        return Stream.of(MCL.BN254, MCL.BLS12_381).flatMap(a ->
                Stream.of(256, 512, 1024).flatMap(b ->
                        Stream.of(Arguments.of(a, b))
                )
        );
    }

    public static Stream<Arguments> GetPBCInvertkSmall() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                Stream.of(8, 16, 24).flatMap(b ->
                        Stream.of(Arguments.of(a, false, b), Arguments.of(a, true, b))
                )
        );
    }

    public static Stream<Arguments> GetPBCInvertkn() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                Stream.of(128, 256, 512).flatMap(b ->
                        Stream.of(16, 32, 64).flatMap(c ->
                                Stream.of(Arguments.of(a, false, b, c), Arguments.of(a, true, b, c))
                        )
                )
        );
    }

    public static Stream<Arguments> GetMCLInvertkn() {
        return Stream.of(MCL.BN254, MCL.BLS12_381).flatMap(a ->
                Stream.of(128, 256, 512).flatMap(b ->
                        Stream.of(16, 32, 64).flatMap(c ->
                                Stream.of(Arguments.of(a, b, c))
                        )
                )
        );
    }

    public static Stream<Arguments> GetPBCInvertGroupn() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                EnumSet.allOf(Group.class).stream().flatMap(b ->
                        Stream.of(16, 32, 64).flatMap(c ->
                                Stream.of(Arguments.of(a, false, b, c), Arguments.of(a, true, b, c))
                        )
                )
        );
    }

    public static Stream<Arguments> GetMCLInvertGroupn() {
        return Stream.of(MCL.BN254, MCL.BLS12_381).flatMap(a ->
                Stream.of(16, 32, 64).flatMap(b ->
                        Stream.of(Arguments.of(a, b))
                )
        );
    }

    public static Stream<Arguments> GetMCLInvertkSmall() {
        return Stream.of(MCL.BN254, MCL.BLS12_381).flatMap(a ->
                Stream.of(8, 16, 24).flatMap(b ->
                        Stream.of(Arguments.of(a, b))
                )
        );
    }

    @BeforeEach
    void initTest() {
        InitialLib();
    }
    @DisplayName("test paper 《Redactable Blockchain in Decentralized Setting》")
    @Nested
    class RedactableBlockchainInDecentralizedSettingTest {
        @DisplayName("test DPCH_MXN_2022")
        @Nested
        class DPCH_MXN_2022_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} author number {1} lambda = {2}")
            @MethodSource("PBCHTest#GetPBCSymmAuthBigLambda")
            void JPBCTest(curve.PBC curve, int auth_num, int lambda) {
                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC scheme = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC(lambda);
                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.PublicParam SP = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.PublicParam(curve, false);
                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.MasterPublicKey MPK = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.MasterPublicKey();
                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.MasterSecretKey MSK = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.MasterSecretKey();
                scheme.SetUp(MPK, MSK, SP);

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(SP.GP_MA_ABE.GP.Zr);
                BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                LSSS.GenLSSSMatrices(MSP, pl, "(A|FF)&(DDDD|(BB&CCC))");

                String GID1 = "WCjrCK_gid";
                String GID2 = "gid2";

                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Modifier mod1 = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Modifier(GID1);
                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Modifier mod2 = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Modifier(GID2);

                scheme.ModSetup(mod1, SP, MSK);
                scheme.ModSetup(mod2, SP, MSK);

                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Authority[] auths = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Authority[auth_num];
                for (int i = 0; i < auth_num; ++i) auths[i] = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Authority("auth_" + i);

                auths[0].MA_ABE_Auth.control_attr.add("A");
                auths[1].MA_ABE_Auth.control_attr.add("BB");
                auths[2].MA_ABE_Auth.control_attr.add("CCC");
                auths[3].MA_ABE_Auth.control_attr.add("DDDD");
                auths[4].MA_ABE_Auth.control_attr.add("E");
                auths[5].MA_ABE_Auth.control_attr.add("FF");

                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.PublicKeyGroup PKG = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.PublicKeyGroup();
                for (int i = 0; i < auth_num; ++i) scheme.AuthSetup(auths[i], SP);
                for (int i = 0; i < auth_num; ++i) PKG.AddPK(auths[i]);

                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.SecretKeyGroup SKG1 = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.SecretKeyGroup();
                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.SecretKeyGroup SKG3 = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.SecretKeyGroup();
                scheme.ModKeyGen(mod1, SP, MPK, auths[0], "A");
                SKG1.AddSK(mod1);
                SKG3.AddSK(mod1);
                scheme.ModKeyGen(mod1, SP, MPK, auths[3], "DDDD");
                SKG1.AddSK(mod1);
                scheme.ModKeyGen(mod1, SP, MPK, auths[4], "E");
                SKG1.AddSK(mod1);

                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.SecretKeyGroup SKG2 = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.SecretKeyGroup();
                scheme.ModKeyGen(mod2, SP, MPK, auths[1], "BB");
                SKG2.AddSK(mod2);
                SKG3.AddSK(mod2);
                scheme.ModKeyGen(mod2, SP, MPK, auths[2], "CCC");
                SKG2.AddSK(mod2);
                SKG3.AddSK(mod2);
                scheme.ModKeyGen(mod2, SP, MPK, auths[5], "FF");
                SKG2.AddSK(mod2);

                String m1 = "WCjrCK";
                String m2 = "123";

                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.HashValue h1 = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.HashValue();
                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.HashValue h2 = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.HashValue();

                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Randomness r1 = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Randomness();
                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Randomness r2 = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Randomness();
                ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Randomness r1_p = new ChameleonHash.PBCH.DEPRECATED.DPCH_MXN_2022.PBC.Randomness();

                scheme.Hash(h1, r1, PKG, MSP, SP, MPK, m1);
                assertTrue(scheme.Check(h1, r1, MPK, m1), "H(m1) valid");
                assertFalse(scheme.Check(h1, r1, MPK, m2), "H(m2) invalid");

                scheme.Hash(h2, r2, PKG, MSP, SP, MPK, m2);
                assertTrue(scheme.Check(h2, r2, MPK, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, MPK, m1), "H(m1) invalid");

                scheme.Adapt(r1_p, h1, r1, PKG, SKG1, MSP, SP, MPK, MSK, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, MPK, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, MPK, m1), "Adapt(m1) invalid");

                scheme.Adapt(r1_p, h1, r1, PKG, SKG2, MSP, SP, MPK, MSK, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, MPK, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, MPK, m1), "Adapt(m1) invalid");
            }
        }
    }
}
