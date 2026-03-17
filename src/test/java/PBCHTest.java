import ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL_swap;
import ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.*;
import base.BinaryTree.PBC;
import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import curve.Group;
import curve.MCL;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import utils.BooleanFormulaParser;
import utils.Func;

import java.util.EnumSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
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

    @DisplayName("test paper 《Redactable Transactions in Consortium Blockchain Controlled by Multi-authority CP-ABE》")
    @Nested
    class RedactableTransactionsInConsortiumBlockchainControlledByMultiAuthorityCPABETest {
        @DisplayName("test MAPCH_ZLW_2021")
        @Nested
        class MAPCH_ZLW_2021_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} author number {1} lambda = {2}")
            @MethodSource("PBCHTest#GetPBCSymmAuth")
            void JPBCTest(curve.PBC curve, int auth_num, int lambda) {
                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC scheme = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC(lambda);
                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.PublicParam SP = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.PublicParam(curve);
                scheme.SetUp(SP);

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(SP.pp_ABE.GP.Zr);
                BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                LSSS.GenLSSSMatrices(MSP, pl, "(A|FF)&(DDDD|(BB&CCC))");

                String GID1 = "WCjrCK";
                String GID2 = "gid2";
                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.SecretKey SK1 = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.SecretKey();
                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.SecretKey SK2 = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.SecretKey();

                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.Authority[] auths = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.Authority[auth_num];
                for (int i = 0; i < auth_num; ++i)
                    auths[i] = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.Authority("auth_" + i, SP);

                auths[0].MA_ABE_Auth.control_attr.add("A");
                auths[1].MA_ABE_Auth.control_attr.add("BB");
                auths[2].MA_ABE_Auth.control_attr.add("CCC");
                auths[3].MA_ABE_Auth.control_attr.add("DDDD");
                auths[4].MA_ABE_Auth.control_attr.add("E");
                auths[5].MA_ABE_Auth.control_attr.add("FF");

                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.PublicKeyGroup PKG = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.PublicKeyGroup(SP);
                for (int i = 0; i < auth_num; ++i) scheme.AuthSetup(auths[i]);
                for (int i = 0; i < auth_num; ++i) PKG.AddPK(auths[i]);

                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.SecretKeyGroup SKG1 = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.SecretKeyGroup();
                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.SecretKeyGroup SKG3 = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.SecretKeyGroup();
                scheme.KeyGen(auths[0], SK1, GID1, "A");
                SKG1.AddSK(SK1);
                SKG3.AddSK(SK1);
                scheme.KeyGen(auths[3], SK1, GID1, "DDDD");
                SKG1.AddSK(SK1);
                scheme.KeyGen(auths[4], SK1, GID1, "E");
                SKG1.AddSK(SK1);

                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.SecretKeyGroup SKG2 = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.SecretKeyGroup();
                scheme.KeyGen(auths[1], SK2, GID2, "BB");
                SKG2.AddSK(SK2);
                SKG3.AddSK(SK2);
                scheme.KeyGen(auths[2], SK2, GID2, "CCC");
                SKG2.AddSK(SK2);
                SKG3.AddSK(SK2);
                scheme.KeyGen(auths[5], SK2, GID2, "FF");
                SKG2.AddSK(SK2);

                String m1 = "WCjrCK";
                String m2 = "123";

                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.HashValue h1 = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.HashValue();
                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.HashValue h2 = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.HashValue();

                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.Randomness r1 = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.Randomness();
                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.Randomness r2 = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.Randomness();
                ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.Randomness r1_p = new ChameleonHash.PBCH.DEPRECATED.MAPCH_ZLW_2021.PBC.Randomness();

                scheme.Hash(h1, r1, PKG, MSP, m1);
                assertTrue(scheme.Check(h1, r1, PKG, m1), "H(m1) valid");
                assertFalse(scheme.Check(h1, r1, PKG, m2), "H(m2) invalid");
                scheme.Hash(h2, r2, PKG, MSP, m2);
                assertTrue(scheme.Check(h2, r2, PKG, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, PKG, m1), "H(m1) invalid");

                scheme.Adapt(r1_p, h1, r1, PKG, SKG1, MSP, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, PKG, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, PKG, m1), "Adapt(m1) invalid");
            }
        }
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

    @DisplayName("test paper 《Revocable Policy-Based Chameleon Hash》")
    @Nested
    class RevocablePolicyBasedChameleonHashTest {
        @DisplayName("test RPCH_XNM_2021")
        @Nested
        class RPCH_XNM_2021_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} swap_G1G2 {1} k = {2} leaf node = {3}")
            @MethodSource("PBCHTest#GetPBCInvertkn")
            void JPBCTest(curve.PBC curve, boolean swap_G1G2, int k, int n) {
                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC scheme = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC(k);
                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.PublicParam SP = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.PublicParam(curve, swap_G1G2);
                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.MasterPublicKey mpk = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.MasterPublicKey();
                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.MasterSecretKey msk = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.MasterSecretKey();
                scheme.SetUp(mpk, msk, SP);

                base.BinaryTree.PBC BT = new PBC(n);
                base.BinaryTree.PBC.RevokeList rl = new base.BinaryTree.PBC.RevokeList();

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(SP.GP.Zr);
                BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                S1.attrs.add("A");
                S1.attrs.add("DDDD");

                BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                S2.attrs.add("BB");
                S2.attrs.add("CCC");

                BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                S3.attrs.add("A");
                S3.attrs.add("BB");
                S3.attrs.add("CCC");

                Element id1 = SP.GP.GetZrElement();
                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.SecretKey sk1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.SecretKey();
                scheme.KeyGen(sk1, BT, SP, mpk, msk, S1, id1);

                Element id2 = SP.GP.GetZrElement();
                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.SecretKey sk2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.SecretKey();
                scheme.KeyGen(sk2, BT, SP, mpk, msk, S2, id2);

                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.SecretKey sk3 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.SecretKey();
                scheme.KeyGen(sk3, BT, SP, mpk, msk, S3, id1);

                scheme.Revoke(rl, id1, 10);
                scheme.Revoke(rl, id2, 100);

                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.UpdateKey ku1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.UpdateKey();
                scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.UpdateKey ku2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.UpdateKey();
                scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.DecryptKey dk_1_1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.DecryptKey dk_1_2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.DecryptKey dk_2_1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.DecryptKey dk_2_2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.DecryptKey dk_3_1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.DecryptKey dk_3_2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                String m1 = "WCjrCK";
                String m2 = "123";

                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.HashValue h1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.HashValue();
                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.HashValue h2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.HashValue();
                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.Randomness r1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.Randomness();
                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.Randomness r2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.Randomness();
                ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.Randomness r1_p = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.PBC.Randomness();

                scheme.Hash(h1, r1, SP, mpk, MSP, m1, 5);
                assertTrue(scheme.Check(h1, r1, mpk, m1), "H(m1) valid");
                assertFalse(scheme.Check(h1, r1, mpk, m2), "H(m2) invalid");

                scheme.Hash(h2, r2, SP, mpk, MSP, m2, 50);
                assertTrue(scheme.Check(h2, r2, mpk, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, mpk, m1), "H(m1) invalid");

                scheme.Adapt(r1_p, h1, r1, SP, mpk, dk_1_1, MSP, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, mpk, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, mpk, m1), "Adapt(m1) invalid");

                try {
                    scheme.Adapt(r1_p, h1, r1, SP, mpk, dk_2_1, MSP, m1, m2);
                    assertFalse(scheme.Check(h1, r1_p, mpk, m2), "policy false");
                    assertFalse(scheme.Check(h1, r1_p, mpk, m1), "policy false");
                } catch (RuntimeException e) {
                    // policy false
                }

                scheme.Adapt(r1_p, h1, r1, SP, mpk, dk_3_1, MSP, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, mpk, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, mpk, m1), "Adapt(m1) invalid");

                try {
                    scheme.Adapt(r1_p, h2, r2, SP, mpk, dk_1_1, MSP, m2, m1);
                    assertFalse(scheme.Check(h2, r1_p, mpk, m1), "different time");
                    assertFalse(scheme.Check(h2, r1_p, mpk, m2), "different time");
                } catch (RuntimeException e) {
                    // different time
                }

                assertThrows(NullPointerException.class, () -> {
                    scheme.Adapt(r1_p, h2, r2, SP, mpk, dk_1_2, MSP, m2, m1);
                    assertFalse(scheme.Check(h2, r1_p, mpk, m1), "different time");
                    assertFalse(scheme.Check(h2, r1_p, mpk, m2), "different time");
                }, "id1 expired");
            }

            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} CH Group = G1 k = {1} leaf node = {2}")
            @MethodSource("PBCHTest#GetMCLInvertkn")
            void MCLTest(MCL curve, int k, int n) {
                Func.MCLInit(curve);
                {
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL scheme = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL(k);
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.PublicParam SP = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.PublicParam();
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.MasterPublicKey mpk = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.MasterPublicKey();
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.MasterSecretKey msk = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.MasterSecretKey();
                    scheme.SetUp(mpk, msk);

                    base.BinaryTree.MCL_G1 BT = new base.BinaryTree.MCL_G1(n);
                    base.BinaryTree.MCL_G1.RevokeList rl = new base.BinaryTree.MCL_G1.RevokeList();

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    S1.attrs.add("A");
                    S1.attrs.add("DDDD");

                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                    S3.attrs.add("A");
                    S3.attrs.add("BB");
                    S3.attrs.add("CCC");

                    G1 id1 = new G1();
                    Func.GetMCLG1RandomElement(id1);
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.SecretKey sk1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.SecretKey();
                    scheme.KeyGen(sk1, BT, SP, mpk, msk, S1, id1);

                    G1 id2 = new G1();
                    Func.GetMCLG1RandomElement(id2);
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.SecretKey sk2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.SecretKey();
                    scheme.KeyGen(sk2, BT, SP, mpk, msk, S2, id2);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.SecretKey sk3 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.SecretKey();
                    scheme.KeyGen(sk3, BT, SP, mpk, msk, S3, id1);

                    scheme.Revoke(rl, id1, 10);
                    scheme.Revoke(rl, id2, 100);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.UpdateKey ku1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.UpdateKey();
                    scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.UpdateKey ku2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.UpdateKey();
                    scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.DecryptKey dk_1_1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.DecryptKey dk_1_2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.DecryptKey dk_2_1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.DecryptKey dk_2_2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.DecryptKey dk_3_1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.DecryptKey dk_3_2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                    String m1 = "WCjrCK";
                    String m2 = "123";

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.HashValue h1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.HashValue();
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.HashValue h2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.HashValue();
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.Randomness r1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.Randomness();
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.Randomness r2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.Randomness();
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.Randomness r1_p = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL.Randomness();

                    scheme.Hash(h1, r1, SP, mpk, MSP, m1, 5);
                    assertTrue(scheme.Check(h1, r1, mpk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, mpk, m2), "H(m2) invalid");

                    scheme.Hash(h2, r2, SP, mpk, MSP, m2, 50);
                    assertTrue(scheme.Check(h2, r2, mpk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, mpk, m1), "H(m1) invalid");

                    scheme.Adapt(r1_p, h1, r1, SP, mpk, dk_1_1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, mpk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, mpk, m1), "Adapt(m1) invalid");

                    try {
                        scheme.Adapt(r1_p, h1, r1, SP, mpk, dk_2_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, mpk, m2), "policy false");
                        assertFalse(scheme.Check(h1, r1_p, mpk, m1), "policy false");
                    } catch (RuntimeException e) {
                        // policy false
                    }

                    scheme.Adapt(r1_p, h1, r1, SP, mpk, dk_3_1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, mpk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, mpk, m1), "Adapt(m1) invalid");

                    try {
                        scheme.Adapt(r1_p, h2, r2, SP, mpk, dk_1_1, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, mpk, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, mpk, m2), "different time");
                    } catch (RuntimeException e) {
                        // different time
                    }

                    assertThrows(NullPointerException.class, () -> {
                        scheme.Adapt(r1_p, h2, r2, SP, mpk, dk_1_2, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, mpk, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, mpk, m2), "different time");
                    }, "id1 expired");
                }
                {
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap scheme = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap(k);
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.PublicParam SP = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.PublicParam();
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.MasterPublicKey mpk = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.MasterPublicKey();
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.MasterSecretKey msk = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.MasterSecretKey();
                    scheme.SetUp(mpk, msk);

                    base.BinaryTree.MCL_G2 BT = new base.BinaryTree.MCL_G2(n);
                    base.BinaryTree.MCL_G2.RevokeList rl = new base.BinaryTree.MCL_G2.RevokeList();

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    S1.attrs.add("A");
                    S1.attrs.add("DDDD");

                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                    S3.attrs.add("A");
                    S3.attrs.add("BB");
                    S3.attrs.add("CCC");

                    G2 id1 = new G2();
                    Func.GetMCLG2RandomElement(id1);
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.SecretKey sk1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.SecretKey();
                    scheme.KeyGen(sk1, BT, SP, mpk, msk, S1, id1);

                    G2 id2 = new G2();
                    Func.GetMCLG2RandomElement(id2);
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.SecretKey sk2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.SecretKey();
                    scheme.KeyGen(sk2, BT, SP, mpk, msk, S2, id2);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.SecretKey sk3 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.SecretKey();
                    scheme.KeyGen(sk3, BT, SP, mpk, msk, S3, id1);

                    scheme.Revoke(rl, id1, 10);
                    scheme.Revoke(rl, id2, 100);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.UpdateKey ku1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.UpdateKey();
                    scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.UpdateKey ku2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.UpdateKey();
                    scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.DecryptKey dk_1_1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.DecryptKey dk_1_2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.DecryptKey dk_2_1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.DecryptKey dk_2_2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.DecryptKey dk_3_1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.DecryptKey dk_3_2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                    String m1 = "WCjrCK";
                    String m2 = "123";

                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.HashValue h1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.HashValue();
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.HashValue h2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.HashValue();
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.Randomness r1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.Randomness();
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.Randomness r2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.Randomness();
                    ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.Randomness r1_p = new ChameleonHash.PBCH.DEPRECATED.RPCH_XNM_2021.MCL_swap.Randomness();

                    scheme.Hash(h1, r1, SP, mpk, MSP, m1, 5);
                    assertTrue(scheme.Check(h1, r1, mpk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, mpk, m2), "H(m2) invalid");

                    scheme.Hash(h2, r2, SP, mpk, MSP, m2, 50);
                    assertTrue(scheme.Check(h2, r2, mpk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, mpk, m1), "H(m1) invalid");

                    scheme.Adapt(r1_p, h1, r1, SP, mpk, dk_1_1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, mpk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, mpk, m1), "Adapt(m1) invalid");

                    try {
                        scheme.Adapt(r1_p, h1, r1, SP, mpk, dk_2_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, mpk, m2), "policy false");
                        assertFalse(scheme.Check(h1, r1_p, mpk, m1), "policy false");
                    } catch (RuntimeException e) {
                        // policy false
                    }

                    scheme.Adapt(r1_p, h1, r1, SP, mpk, dk_3_1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, mpk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, mpk, m1), "Adapt(m1) invalid");

                    try {
                        scheme.Adapt(r1_p, h2, r2, SP, mpk, dk_1_1, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, mpk, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, mpk, m2), "different time");
                    } catch (RuntimeException e) {
                        // different time
                    }

                    assertThrows(NullPointerException.class, () -> {
                        scheme.Adapt(r1_p, h2, r2, SP, mpk, dk_1_2, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, mpk, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, mpk, m2), "different time");
                    }, "id1 expired");
                }
            }
        }
    }

    @DisplayName("test paper 《Revocable Policy-Based ChameleonHash for Blockchain Rewriting》")
    @Nested
    class RevocablePolicyBasedChameleonHashForBlockchainRewritingTest {
        @DisplayName("test RPCH_TMM_2022")
        @Nested
        class RPCH_TMM_2022_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} swap_G1G2 {1} CH group = {2} leaf node = {3}")
            @MethodSource("PBCHTest#GetPBCInvertGroupn")
            void JPBCTest(curve.PBC curve, boolean swap_G1G2, Group group, int n) {
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC scheme = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC();
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.PublicParam SP = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.PublicParam(curve, swap_G1G2, group);
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.MasterPublicKey mpk = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.MasterPublicKey();
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.MasterSecretKey msk = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.MasterSecretKey();
                scheme.SetUp(mpk, msk, SP);

                base.BinaryTree.PBC BT = new PBC(n);
                base.BinaryTree.PBC.RevokeList rl = new base.BinaryTree.PBC.RevokeList();

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(SP.GP.Zr);
                BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                S1.attrs.add("A");
                S1.attrs.add("DDDD");

                BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                S2.attrs.add("BB");
                S2.attrs.add("CCC");

                BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                S3.attrs.add("A");
                S3.attrs.add("BB");
                S3.attrs.add("CCC");

                Element id1 = SP.GP.GetZrElement();
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.PublicKey pk1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.PublicKey();
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.SecretKey sk1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.SecretKey();
                scheme.KeyGen(pk1, sk1, BT, SP, mpk, msk, S1, id1);

                Element id2 = SP.GP.GetZrElement();
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.PublicKey pk2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.PublicKey();
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.SecretKey sk2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.SecretKey();
                scheme.KeyGen(pk2, sk2, BT, SP, mpk, msk, S2, id2);

                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.PublicKey pk3 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.PublicKey();
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.SecretKey sk3 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.SecretKey();
                scheme.KeyGen(pk3, sk3, BT, SP, mpk, msk, S3, id1);

                scheme.Revoke(rl, id1, 10);
                scheme.Revoke(rl, id2, 100);

                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.UpdateKey ku1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.UpdateKey();
                scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.UpdateKey ku2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.UpdateKey();
                scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.DecryptKey dk_1_1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.DecryptKey dk_1_2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.DecryptKey dk_2_1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.DecryptKey dk_2_2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.DecryptKey dk_3_1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.DecryptKey dk_3_2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                Element m1 = SP.GP_CHET.GetZrElement();
                Element m2 = SP.GP_CHET.GetZrElement();

                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.HashValue h1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.HashValue();
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.HashValue h2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.HashValue();
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.Randomness r1 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.Randomness();
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.Randomness r2 = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.Randomness();
                ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.Randomness r1_p = new ChameleonHash.PBCH.DEPRECATED.RPCH_TMM_2022.PBC.Randomness();

                scheme.Hash(h1, r1, SP, mpk, pk1, MSP, m1, 5);
                assertTrue(scheme.Check(h1, r1, pk1, m1), "H(m1) valid");
                assertFalse(scheme.Check(h1, r1, pk1, m2), "H(m2) invalid");
                assertFalse(scheme.Check(h1, r1, pk2, m1), "H(pk2, m1) invalid");
                assertFalse(scheme.Check(h1, r1, pk1, m2), "H(pk2, m2) invalid");

                scheme.Hash(h2, r2, SP, mpk, pk2, MSP, m2, 50);
                assertTrue(scheme.Check(h2, r2, pk2, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pk2, m1), "H(m1) invalid");

                scheme.Adapt(r1_p, h1, r1, SP, pk1, dk_1_1, MSP, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pk1, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, pk1, m1), "Adapt(m1) invalid");

                assertThrows(RuntimeException.class, () -> {
                    scheme.Adapt(r1_p, h1, r1, SP, pk2, dk_2_1, MSP, m1, m2);
                    assertFalse(scheme.Check(h1, r1_p, pk2, m2), "policy false");
                    assertFalse(scheme.Check(h1, r1_p, pk2, m1), "policy false");
                }, "policy false");

                assertThrows(RuntimeException.class, () -> {
                    scheme.Adapt(r1_p, h1, r1, SP, pk3, dk_3_1, MSP, m1, m2);
                    assertFalse(scheme.Check(h1, r1_p, pk3, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pk3, m1), "Adapt(m1) invalid");
                }, "wrong hash");

                assertThrows(RuntimeException.class, () -> {
                    scheme.Adapt(r1_p, h2, r2, SP, pk1, dk_1_1, MSP, m2, m1);
                    assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                    assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                }, "different time");

                try {
                    scheme.Adapt(r1_p, h2, r2, SP, pk1, dk_1_2, MSP, m2, m1);
                    assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                    assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                } catch (Exception e) {
                    // id1 expired
                }
            }

            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} CH Group = G1 leaf node = {1}")
            @MethodSource("PBCHTest#GetMCLInvertGroupn")
            void MCLG1Test(curve.MCL curve, int n) {
                Func.MCLInit(curve);
                {
                    MCL_G1 scheme = new MCL_G1();
                    MCL_G1.PublicParam SP = new MCL_G1.PublicParam();
                    MCL_G1.MasterPublicKey mpk = new MCL_G1.MasterPublicKey();
                    MCL_G1.MasterSecretKey msk = new MCL_G1.MasterSecretKey();
                    scheme.SetUp(mpk, msk, SP);

                    base.BinaryTree.MCL_G1 BT = new base.BinaryTree.MCL_G1(n);
                    base.BinaryTree.MCL_G1.RevokeList rl = new base.BinaryTree.MCL_G1.RevokeList();

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    S1.attrs.add("A");
                    S1.attrs.add("DDDD");

                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                    S3.attrs.add("A");
                    S3.attrs.add("BB");
                    S3.attrs.add("CCC");

                    G1 id1 = new G1();
                    Func.GetMCLG1RandomElement(id1);
                    MCL_G1.PublicKey pk1 = new MCL_G1.PublicKey();
                    MCL_G1.SecretKey sk1 = new MCL_G1.SecretKey();
                    scheme.KeyGen(pk1, sk1, BT, SP, mpk, msk, S1, id1);

                    G1 id2 = new G1();
                    Func.GetMCLG1RandomElement(id2);
                    MCL_G1.PublicKey pk2 = new MCL_G1.PublicKey();
                    MCL_G1.SecretKey sk2 = new MCL_G1.SecretKey();
                    scheme.KeyGen(pk2, sk2, BT, SP, mpk, msk, S2, id2);

                    MCL_G1.PublicKey pk3 = new MCL_G1.PublicKey();
                    MCL_G1.SecretKey sk3 = new MCL_G1.SecretKey();
                    scheme.KeyGen(pk3, sk3, BT, SP, mpk, msk, S3, id1);

                    scheme.Revoke(rl, id1, 10);
                    scheme.Revoke(rl, id2, 100);

                    MCL_G1.UpdateKey ku1 = new MCL_G1.UpdateKey();
                    scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                    MCL_G1.UpdateKey ku2 = new MCL_G1.UpdateKey();
                    scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                    MCL_G1.DecryptKey dk_1_1 = new MCL_G1.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                    MCL_G1.DecryptKey dk_1_2 = new MCL_G1.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                    MCL_G1.DecryptKey dk_2_1 = new MCL_G1.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                    MCL_G1.DecryptKey dk_2_2 = new MCL_G1.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                    MCL_G1.DecryptKey dk_3_1 = new MCL_G1.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                    MCL_G1.DecryptKey dk_3_2 = new MCL_G1.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                    Fr m1 = new Fr();
                    Func.GetMCLZrRandomElement(m1);
                    Fr m2 = new Fr();
                    Func.GetMCLZrRandomElement(m2);

                    MCL_G1.HashValue h1 = new MCL_G1.HashValue();
                    MCL_G1.HashValue h2 = new MCL_G1.HashValue();
                    MCL_G1.Randomness r1 = new MCL_G1.Randomness();
                    MCL_G1.Randomness r2 = new MCL_G1.Randomness();
                    MCL_G1.Randomness r1_p = new MCL_G1.Randomness();

                    scheme.Hash(h1, r1, SP, mpk, pk1, MSP, m1, 5);
                    assertTrue(scheme.Check(h1, r1, pk1, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pk1, m2), "H(m2) invalid");
                    assertFalse(scheme.Check(h1, r1, pk2, m1), "H(pk2, m1) invalid");
                    assertFalse(scheme.Check(h1, r1, pk1, m2), "H(pk2, m2) invalid");

                    scheme.Hash(h2, r2, SP, mpk, pk2, MSP, m2, 50);
                    assertTrue(scheme.Check(h2, r2, pk2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pk2, m1), "H(m1) invalid");

                    scheme.Adapt(r1_p, h1, r1, pk1, dk_1_1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pk1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pk1, m1), "Adapt(m1) invalid");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h1, r1, pk2, dk_2_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, pk2, m2), "policy false");
                        assertFalse(scheme.Check(h1, r1_p, pk2, m1), "policy false");
                    }, "policy false");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h1, r1, pk3, dk_3_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, pk3, m2), "Adapt(m2) valid");
                        assertFalse(scheme.Check(h1, r1_p, pk3, m1), "Adapt(m1) invalid");
                    }, "wrong hash");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h2, r2, pk1, dk_1_1, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                    }, "different time");

                    try {
                        scheme.Adapt(r1_p, h2, r2, pk1, dk_1_2, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                    } catch (Exception e) {
                        // id1 expired
                    }
                }
                {
                    MCL_G1_swap scheme = new MCL_G1_swap();
                    MCL_G1_swap.PublicParam SP = new MCL_G1_swap.PublicParam();
                    MCL_G1_swap.MasterPublicKey mpk = new MCL_G1_swap.MasterPublicKey();
                    MCL_G1_swap.MasterSecretKey msk = new MCL_G1_swap.MasterSecretKey();
                    scheme.SetUp(mpk, msk, SP);

                    base.BinaryTree.MCL_G2 BT = new base.BinaryTree.MCL_G2(n);
                    base.BinaryTree.MCL_G2.RevokeList rl = new base.BinaryTree.MCL_G2.RevokeList();

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    S1.attrs.add("A");
                    S1.attrs.add("DDDD");

                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                    S3.attrs.add("A");
                    S3.attrs.add("BB");
                    S3.attrs.add("CCC");

                    G2 id1 = new G2();
                    Func.GetMCLG2RandomElement(id1);
                    MCL_G1_swap.PublicKey pk1 = new MCL_G1_swap.PublicKey();
                    MCL_G1_swap.SecretKey sk1 = new MCL_G1_swap.SecretKey();
                    scheme.KeyGen(pk1, sk1, BT, SP, mpk, msk, S1, id1);

                    G2 id2 = new G2();
                    Func.GetMCLG2RandomElement(id2);
                    MCL_G1_swap.PublicKey pk2 = new MCL_G1_swap.PublicKey();
                    MCL_G1_swap.SecretKey sk2 = new MCL_G1_swap.SecretKey();
                    scheme.KeyGen(pk2, sk2, BT, SP, mpk, msk, S2, id2);

                    MCL_G1_swap.PublicKey pk3 = new MCL_G1_swap.PublicKey();
                    MCL_G1_swap.SecretKey sk3 = new MCL_G1_swap.SecretKey();
                    scheme.KeyGen(pk3, sk3, BT, SP, mpk, msk, S3, id1);

                    scheme.Revoke(rl, id1, 10);
                    scheme.Revoke(rl, id2, 100);

                    MCL_G1_swap.UpdateKey ku1 = new MCL_G1_swap.UpdateKey();
                    scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                    MCL_G1_swap.UpdateKey ku2 = new MCL_G1_swap.UpdateKey();
                    scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                    MCL_G1_swap.DecryptKey dk_1_1 = new MCL_G1_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                    MCL_G1_swap.DecryptKey dk_1_2 = new MCL_G1_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                    MCL_G1_swap.DecryptKey dk_2_1 = new MCL_G1_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                    MCL_G1_swap.DecryptKey dk_2_2 = new MCL_G1_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                    MCL_G1_swap.DecryptKey dk_3_1 = new MCL_G1_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                    MCL_G1_swap.DecryptKey dk_3_2 = new MCL_G1_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                    Fr m1 = new Fr();
                    Func.GetMCLZrRandomElement(m1);
                    Fr m2 = new Fr();
                    Func.GetMCLZrRandomElement(m2);

                    MCL_G1_swap.HashValue h1 = new MCL_G1_swap.HashValue();
                    MCL_G1_swap.HashValue h2 = new MCL_G1_swap.HashValue();
                    MCL_G1_swap.Randomness r1 = new MCL_G1_swap.Randomness();
                    MCL_G1_swap.Randomness r2 = new MCL_G1_swap.Randomness();
                    MCL_G1_swap.Randomness r1_p = new MCL_G1_swap.Randomness();

                    scheme.Hash(h1, r1, SP, mpk, pk1, MSP, m1, 5);
                    assertTrue(scheme.Check(h1, r1, pk1, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pk1, m2), "H(m2) invalid");
                    assertFalse(scheme.Check(h1, r1, pk2, m1), "H(pk2, m1) invalid");
                    assertFalse(scheme.Check(h1, r1, pk1, m2), "H(pk2, m2) invalid");

                    scheme.Hash(h2, r2, SP, mpk, pk2, MSP, m2, 50);
                    assertTrue(scheme.Check(h2, r2, pk2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pk2, m1), "H(m1) invalid");

                    scheme.Adapt(r1_p, h1, r1, pk1, dk_1_1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pk1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pk1, m1), "Adapt(m1) invalid");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h1, r1, pk2, dk_2_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, pk2, m2), "policy false");
                        assertFalse(scheme.Check(h1, r1_p, pk2, m1), "policy false");
                    }, "policy false");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h1, r1, pk3, dk_3_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, pk3, m2), "Adapt(m2) valid");
                        assertFalse(scheme.Check(h1, r1_p, pk3, m1), "Adapt(m1) invalid");
                    }, "wrong hash");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h2, r2, pk1, dk_1_1, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                    }, "different time");

                    try {
                        scheme.Adapt(r1_p, h2, r2, pk1, dk_1_2, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                    } catch (Exception e) {
                        // id1 expired
                    }
                }
            }

            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} CH Group = G2 leaf node = {1}")
            @MethodSource("PBCHTest#GetMCLInvertGroupn")
            void MCLG2Test(curve.MCL curve, int n) {
                Func.MCLInit(curve);
                {
                    MCL_G2 scheme = new MCL_G2();
                    MCL_G2.PublicParam SP = new MCL_G2.PublicParam();
                    MCL_G2.MasterPublicKey mpk = new MCL_G2.MasterPublicKey();
                    MCL_G2.MasterSecretKey msk = new MCL_G2.MasterSecretKey();
                    scheme.SetUp(mpk, msk, SP);

                    base.BinaryTree.MCL_G1 BT = new base.BinaryTree.MCL_G1(n);
                    base.BinaryTree.MCL_G1.RevokeList rl = new base.BinaryTree.MCL_G1.RevokeList();

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    S1.attrs.add("A");
                    S1.attrs.add("DDDD");

                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                    S3.attrs.add("A");
                    S3.attrs.add("BB");
                    S3.attrs.add("CCC");

                    G1 id1 = new G1();
                    Func.GetMCLG1RandomElement(id1);
                    MCL_G2.PublicKey pk1 = new MCL_G2.PublicKey();
                    MCL_G2.SecretKey sk1 = new MCL_G2.SecretKey();
                    scheme.KeyGen(pk1, sk1, BT, SP, mpk, msk, S1, id1);

                    G1 id2 = new G1();
                    Func.GetMCLG1RandomElement(id2);
                    MCL_G2.PublicKey pk2 = new MCL_G2.PublicKey();
                    MCL_G2.SecretKey sk2 = new MCL_G2.SecretKey();
                    scheme.KeyGen(pk2, sk2, BT, SP, mpk, msk, S2, id2);

                    MCL_G2.PublicKey pk3 = new MCL_G2.PublicKey();
                    MCL_G2.SecretKey sk3 = new MCL_G2.SecretKey();
                    scheme.KeyGen(pk3, sk3, BT, SP, mpk, msk, S3, id1);

                    scheme.Revoke(rl, id1, 10);
                    scheme.Revoke(rl, id2, 100);

                    MCL_G2.UpdateKey ku1 = new MCL_G2.UpdateKey();
                    scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                    MCL_G2.UpdateKey ku2 = new MCL_G2.UpdateKey();
                    scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                    MCL_G2.DecryptKey dk_1_1 = new MCL_G2.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                    MCL_G2.DecryptKey dk_1_2 = new MCL_G2.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                    MCL_G2.DecryptKey dk_2_1 = new MCL_G2.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                    MCL_G2.DecryptKey dk_2_2 = new MCL_G2.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                    MCL_G2.DecryptKey dk_3_1 = new MCL_G2.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                    MCL_G2.DecryptKey dk_3_2 = new MCL_G2.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                    Fr m1 = new Fr();
                    Func.GetMCLZrRandomElement(m1);
                    Fr m2 = new Fr();
                    Func.GetMCLZrRandomElement(m2);

                    MCL_G2.HashValue h1 = new MCL_G2.HashValue();
                    MCL_G2.HashValue h2 = new MCL_G2.HashValue();
                    MCL_G2.Randomness r1 = new MCL_G2.Randomness();
                    MCL_G2.Randomness r2 = new MCL_G2.Randomness();
                    MCL_G2.Randomness r1_p = new MCL_G2.Randomness();

                    scheme.Hash(h1, r1, SP, mpk, pk1, MSP, m1, 5);
                    assertTrue(scheme.Check(h1, r1, pk1, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pk1, m2), "H(m2) invalid");
                    assertFalse(scheme.Check(h1, r1, pk2, m1), "H(pk2, m1) invalid");
                    assertFalse(scheme.Check(h1, r1, pk1, m2), "H(pk2, m2) invalid");

                    scheme.Hash(h2, r2, SP, mpk, pk2, MSP, m2, 50);
                    assertTrue(scheme.Check(h2, r2, pk2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pk2, m1), "H(m1) invalid");

                    scheme.Adapt(r1_p, h1, r1, pk1, dk_1_1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pk1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pk1, m1), "Adapt(m1) invalid");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h1, r1, pk2, dk_2_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, pk2, m2), "policy false");
                        assertFalse(scheme.Check(h1, r1_p, pk2, m1), "policy false");
                    }, "policy false");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h1, r1, pk3, dk_3_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, pk3, m2), "Adapt(m2) valid");
                        assertFalse(scheme.Check(h1, r1_p, pk3, m1), "Adapt(m1) invalid");
                    }, "wrong hash");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h2, r2, pk1, dk_1_1, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                    }, "different time");

                    try {
                        scheme.Adapt(r1_p, h2, r2, pk1, dk_1_2, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                    } catch (Exception e) {
                        // id1 expired
                    }
                }
                {
                    MCL_G2_swap scheme = new MCL_G2_swap();
                    MCL_G2_swap.PublicParam SP = new MCL_G2_swap.PublicParam();
                    MCL_G2_swap.MasterPublicKey mpk = new MCL_G2_swap.MasterPublicKey();
                    MCL_G2_swap.MasterSecretKey msk = new MCL_G2_swap.MasterSecretKey();
                    scheme.SetUp(mpk, msk, SP);

                    base.BinaryTree.MCL_G2 BT = new base.BinaryTree.MCL_G2(n);
                    base.BinaryTree.MCL_G2.RevokeList rl = new base.BinaryTree.MCL_G2.RevokeList();

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    S1.attrs.add("A");
                    S1.attrs.add("DDDD");

                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                    S3.attrs.add("A");
                    S3.attrs.add("BB");
                    S3.attrs.add("CCC");

                    G2 id1 = new G2();
                    Func.GetMCLG2RandomElement(id1);
                    MCL_G2_swap.PublicKey pk1 = new MCL_G2_swap.PublicKey();
                    MCL_G2_swap.SecretKey sk1 = new MCL_G2_swap.SecretKey();
                    scheme.KeyGen(pk1, sk1, BT, SP, mpk, msk, S1, id1);

                    G2 id2 = new G2();
                    Func.GetMCLG2RandomElement(id2);
                    MCL_G2_swap.PublicKey pk2 = new MCL_G2_swap.PublicKey();
                    MCL_G2_swap.SecretKey sk2 = new MCL_G2_swap.SecretKey();
                    scheme.KeyGen(pk2, sk2, BT, SP, mpk, msk, S2, id2);

                    MCL_G2_swap.PublicKey pk3 = new MCL_G2_swap.PublicKey();
                    MCL_G2_swap.SecretKey sk3 = new MCL_G2_swap.SecretKey();
                    scheme.KeyGen(pk3, sk3, BT, SP, mpk, msk, S3, id1);

                    scheme.Revoke(rl, id1, 10);
                    scheme.Revoke(rl, id2, 100);

                    MCL_G2_swap.UpdateKey ku1 = new MCL_G2_swap.UpdateKey();
                    scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                    MCL_G2_swap.UpdateKey ku2 = new MCL_G2_swap.UpdateKey();
                    scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                    MCL_G2_swap.DecryptKey dk_1_1 = new MCL_G2_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                    MCL_G2_swap.DecryptKey dk_1_2 = new MCL_G2_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                    MCL_G2_swap.DecryptKey dk_2_1 = new MCL_G2_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                    MCL_G2_swap.DecryptKey dk_2_2 = new MCL_G2_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                    MCL_G2_swap.DecryptKey dk_3_1 = new MCL_G2_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                    MCL_G2_swap.DecryptKey dk_3_2 = new MCL_G2_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                    Fr m1 = new Fr();
                    Func.GetMCLZrRandomElement(m1);
                    Fr m2 = new Fr();
                    Func.GetMCLZrRandomElement(m2);

                    MCL_G2_swap.HashValue h1 = new MCL_G2_swap.HashValue();
                    MCL_G2_swap.HashValue h2 = new MCL_G2_swap.HashValue();
                    MCL_G2_swap.Randomness r1 = new MCL_G2_swap.Randomness();
                    MCL_G2_swap.Randomness r2 = new MCL_G2_swap.Randomness();
                    MCL_G2_swap.Randomness r1_p = new MCL_G2_swap.Randomness();

                    scheme.Hash(h1, r1, SP, mpk, pk1, MSP, m1, 5);
                    assertTrue(scheme.Check(h1, r1, pk1, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pk1, m2), "H(m2) invalid");
                    assertFalse(scheme.Check(h1, r1, pk2, m1), "H(pk2, m1) invalid");
                    assertFalse(scheme.Check(h1, r1, pk1, m2), "H(pk2, m2) invalid");

                    scheme.Hash(h2, r2, SP, mpk, pk2, MSP, m2, 50);
                    assertTrue(scheme.Check(h2, r2, pk2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pk2, m1), "H(m1) invalid");

                    scheme.Adapt(r1_p, h1, r1, pk1, dk_1_1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pk1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pk1, m1), "Adapt(m1) invalid");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h1, r1, pk2, dk_2_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, pk2, m2), "policy false");
                        assertFalse(scheme.Check(h1, r1_p, pk2, m1), "policy false");
                    }, "policy false");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h1, r1, pk3, dk_3_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, pk3, m2), "Adapt(m2) valid");
                        assertFalse(scheme.Check(h1, r1_p, pk3, m1), "Adapt(m1) invalid");
                    }, "wrong hash");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h2, r2, pk1, dk_1_1, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                    }, "different time");

                    try {
                        scheme.Adapt(r1_p, h2, r2, pk1, dk_1_2, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                    } catch (Exception e) {
                        // id1 expired
                    }
                }
            }

            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} CH Group = GT leaf node = {1}")
            @MethodSource("PBCHTest#GetMCLInvertGroupn")
            void MCLGTTest(curve.MCL curve, int n) {
                Func.MCLInit(curve);
                {
                    MCL_GT scheme = new MCL_GT();
                    MCL_GT.PublicParam SP = new MCL_GT.PublicParam();
                    MCL_GT.MasterPublicKey mpk = new MCL_GT.MasterPublicKey();
                    MCL_GT.MasterSecretKey msk = new MCL_GT.MasterSecretKey();
                    scheme.SetUp(mpk, msk, SP);

                    base.BinaryTree.MCL_G1 BT = new base.BinaryTree.MCL_G1(n);
                    base.BinaryTree.MCL_G1.RevokeList rl = new base.BinaryTree.MCL_G1.RevokeList();

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    S1.attrs.add("A");
                    S1.attrs.add("DDDD");

                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                    S3.attrs.add("A");
                    S3.attrs.add("BB");
                    S3.attrs.add("CCC");

                    G1 id1 = new G1();
                    Func.GetMCLG1RandomElement(id1);
                    MCL_GT.PublicKey pk1 = new MCL_GT.PublicKey();
                    MCL_GT.SecretKey sk1 = new MCL_GT.SecretKey();
                    scheme.KeyGen(pk1, sk1, BT, SP, mpk, msk, S1, id1);

                    G1 id2 = new G1();
                    Func.GetMCLG1RandomElement(id2);
                    MCL_GT.PublicKey pk2 = new MCL_GT.PublicKey();
                    MCL_GT.SecretKey sk2 = new MCL_GT.SecretKey();
                    scheme.KeyGen(pk2, sk2, BT, SP, mpk, msk, S2, id2);

                    MCL_GT.PublicKey pk3 = new MCL_GT.PublicKey();
                    MCL_GT.SecretKey sk3 = new MCL_GT.SecretKey();
                    scheme.KeyGen(pk3, sk3, BT, SP, mpk, msk, S3, id1);

                    scheme.Revoke(rl, id1, 10);
                    scheme.Revoke(rl, id2, 100);

                    MCL_GT.UpdateKey ku1 = new MCL_GT.UpdateKey();
                    scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                    MCL_GT.UpdateKey ku2 = new MCL_GT.UpdateKey();
                    scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                    MCL_GT.DecryptKey dk_1_1 = new MCL_GT.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                    MCL_GT.DecryptKey dk_1_2 = new MCL_GT.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                    MCL_GT.DecryptKey dk_2_1 = new MCL_GT.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                    MCL_GT.DecryptKey dk_2_2 = new MCL_GT.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                    MCL_GT.DecryptKey dk_3_1 = new MCL_GT.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                    MCL_GT.DecryptKey dk_3_2 = new MCL_GT.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                    Fr m1 = new Fr();
                    Func.GetMCLZrRandomElement(m1);
                    Fr m2 = new Fr();
                    Func.GetMCLZrRandomElement(m2);

                    MCL_GT.HashValue h1 = new MCL_GT.HashValue();
                    MCL_GT.HashValue h2 = new MCL_GT.HashValue();
                    MCL_GT.Randomness r1 = new MCL_GT.Randomness();
                    MCL_GT.Randomness r2 = new MCL_GT.Randomness();
                    MCL_GT.Randomness r1_p = new MCL_GT.Randomness();

                    scheme.Hash(h1, r1, SP, mpk, pk1, MSP, m1, 5);
                    assertTrue(scheme.Check(h1, r1, pk1, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pk1, m2), "H(m2) invalid");
                    assertFalse(scheme.Check(h1, r1, pk2, m1), "H(pk2, m1) invalid");
                    assertFalse(scheme.Check(h1, r1, pk1, m2), "H(pk2, m2) invalid");

                    scheme.Hash(h2, r2, SP, mpk, pk2, MSP, m2, 50);
                    assertTrue(scheme.Check(h2, r2, pk2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pk2, m1), "H(m1) invalid");

                    scheme.Adapt(r1_p, h1, r1, pk1, dk_1_1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pk1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pk1, m1), "Adapt(m1) invalid");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h1, r1, pk2, dk_2_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, pk2, m2), "policy false");
                        assertFalse(scheme.Check(h1, r1_p, pk2, m1), "policy false");
                    }, "policy false");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h1, r1, pk3, dk_3_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, pk3, m2), "Adapt(m2) valid");
                        assertFalse(scheme.Check(h1, r1_p, pk3, m1), "Adapt(m1) invalid");
                    }, "wrong hash");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h2, r2, pk1, dk_1_1, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                    }, "different time");

                    try {
                        scheme.Adapt(r1_p, h2, r2, pk1, dk_1_2, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                    } catch (Exception e) {
                        // id1 expired
                    }
                }
                {
                    MCL_GT_swap scheme = new MCL_GT_swap();
                    MCL_GT_swap.PublicParam SP = new MCL_GT_swap.PublicParam();
                    MCL_GT_swap.MasterPublicKey mpk = new MCL_GT_swap.MasterPublicKey();
                    MCL_GT_swap.MasterSecretKey msk = new MCL_GT_swap.MasterSecretKey();
                    scheme.SetUp(mpk, msk, SP);

                    base.BinaryTree.MCL_G2 BT = new base.BinaryTree.MCL_G2(n);
                    base.BinaryTree.MCL_G2.RevokeList rl = new base.BinaryTree.MCL_G2.RevokeList();

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    S1.attrs.add("A");
                    S1.attrs.add("DDDD");

                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();
                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    BooleanFormulaParser.AttributeList S3 = new BooleanFormulaParser.AttributeList();
                    S3.attrs.add("A");
                    S3.attrs.add("BB");
                    S3.attrs.add("CCC");

                    G2 id1 = new G2();
                    Func.GetMCLG2RandomElement(id1);
                    MCL_GT_swap.PublicKey pk1 = new MCL_GT_swap.PublicKey();
                    MCL_GT_swap.SecretKey sk1 = new MCL_GT_swap.SecretKey();
                    scheme.KeyGen(pk1, sk1, BT, SP, mpk, msk, S1, id1);

                    G2 id2 = new G2();
                    Func.GetMCLG2RandomElement(id2);
                    MCL_GT_swap.PublicKey pk2 = new MCL_GT_swap.PublicKey();
                    MCL_GT_swap.SecretKey sk2 = new MCL_GT_swap.SecretKey();
                    scheme.KeyGen(pk2, sk2, BT, SP, mpk, msk, S2, id2);

                    MCL_GT_swap.PublicKey pk3 = new MCL_GT_swap.PublicKey();
                    MCL_GT_swap.SecretKey sk3 = new MCL_GT_swap.SecretKey();
                    scheme.KeyGen(pk3, sk3, BT, SP, mpk, msk, S3, id1);

                    scheme.Revoke(rl, id1, 10);
                    scheme.Revoke(rl, id2, 100);

                    MCL_GT_swap.UpdateKey ku1 = new MCL_GT_swap.UpdateKey();
                    scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                    MCL_GT_swap.UpdateKey ku2 = new MCL_GT_swap.UpdateKey();
                    scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                    MCL_GT_swap.DecryptKey dk_1_1 = new MCL_GT_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                    MCL_GT_swap.DecryptKey dk_1_2 = new MCL_GT_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                    MCL_GT_swap.DecryptKey dk_2_1 = new MCL_GT_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                    MCL_GT_swap.DecryptKey dk_2_2 = new MCL_GT_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                    MCL_GT_swap.DecryptKey dk_3_1 = new MCL_GT_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                    MCL_GT_swap.DecryptKey dk_3_2 = new MCL_GT_swap.DecryptKey();
                    scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                    Fr m1 = new Fr();
                    Func.GetMCLZrRandomElement(m1);
                    Fr m2 = new Fr();
                    Func.GetMCLZrRandomElement(m2);

                    MCL_GT_swap.HashValue h1 = new MCL_GT_swap.HashValue();
                    MCL_GT_swap.HashValue h2 = new MCL_GT_swap.HashValue();
                    MCL_GT_swap.Randomness r1 = new MCL_GT_swap.Randomness();
                    MCL_GT_swap.Randomness r2 = new MCL_GT_swap.Randomness();
                    MCL_GT_swap.Randomness r1_p = new MCL_GT_swap.Randomness();

                    scheme.Hash(h1, r1, SP, mpk, pk1, MSP, m1, 5);
                    assertTrue(scheme.Check(h1, r1, pk1, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, pk1, m2), "H(m2) invalid");
                    assertFalse(scheme.Check(h1, r1, pk2, m1), "H(pk2, m1) invalid");
                    assertFalse(scheme.Check(h1, r1, pk1, m2), "H(pk2, m2) invalid");

                    scheme.Hash(h2, r2, SP, mpk, pk2, MSP, m2, 50);
                    assertTrue(scheme.Check(h2, r2, pk2, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, pk2, m1), "H(m1) invalid");

                    scheme.Adapt(r1_p, h1, r1, pk1, dk_1_1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, pk1, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, pk1, m1), "Adapt(m1) invalid");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h1, r1, pk2, dk_2_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, pk2, m2), "policy false");
                        assertFalse(scheme.Check(h1, r1_p, pk2, m1), "policy false");
                    }, "policy false");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h1, r1, pk3, dk_3_1, MSP, m1, m2);
                        assertFalse(scheme.Check(h1, r1_p, pk3, m2), "Adapt(m2) valid");
                        assertFalse(scheme.Check(h1, r1_p, pk3, m1), "Adapt(m1) invalid");
                    }, "wrong hash");

                    assertThrows(RuntimeException.class, () -> {
                        scheme.Adapt(r1_p, h2, r2, pk1, dk_1_1, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                    }, "different time");

                    try {
                        scheme.Adapt(r1_p, h2, r2, pk1, dk_1_2, MSP, m2, m1);
                        assertFalse(scheme.Check(h2, r1_p, pk1, m1), "different time");
                        assertFalse(scheme.Check(h2, r1_p, pk1, m2), "different time");
                    } catch (Exception e) {
                        // id1 expired
                    }
                }
            }
        }
    }

    @DisplayName("test paper 《Policy-based Chameleon Hash for Blockchain Rewriting with Black-box Accountability》")
    @Nested
    class PolicyBasedChameleonHashForBlockchainRewritingWithBlackBoxAccountabilityTest {
        @DisplayName("test PCHBA_TLL_2020")
        @Nested
        class PCHBA_TLL_2020_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} swap_G1G2 {1} k = {2}")
            @MethodSource("PBCHTest#GetPBCInvertkSmall")
            void JPBCTest(curve.PBC curve, boolean swap_G1G2, int k) {
                ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC scheme = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC();
                ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.PublicParam SP = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.PublicParam(curve, swap_G1G2);
                ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.MasterPublicKey mpk = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.MasterPublicKey();
                ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.MasterSecretKey msk = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.MasterSecretKey();
                scheme.SetUp(mpk, msk, SP, k);

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(SP.GP.Zr);
                BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();

                S1.attrs.add("A");
                S1.attrs.add("DDDD");

                S2.attrs.add("BB");
                S2.attrs.add("CCC");

                ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.User u1 = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.User(SP, k / 3);
                scheme.AssignUser(u1, mpk, msk);
                scheme.KeyGen(u1, SP, mpk, msk, S1);

                ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.User u2 = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.User(u1, SP, k / 2);
                scheme.AssignUser(u2, mpk, msk);
                scheme.KeyGen(u2, SP, mpk, msk, S2);

                Element m1 = SP.GP.GetZrElement();
                Element m2 = SP.GP.GetZrElement();

                ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.HashValue h1 = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.HashValue();
                ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.HashValue h2 = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.HashValue();
                ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.Randomness r1 = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.Randomness();
                ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.Randomness r2 = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.Randomness();
                ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.Randomness r1_p = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.PBC.Randomness();

                scheme.Hash(h1, r1, SP, mpk, u1, MSP, m1);
                assertTrue(scheme.Check(h1, r1, SP, mpk, m1), "H(m1) valid");
                assertFalse(scheme.Check(h1, r1, SP, mpk, m2), "H(m2) invalid");

                scheme.Hash(h2, r2, SP, mpk, u2, MSP, m2);
                assertTrue(scheme.Check(h2, r2, SP, mpk, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, SP, mpk, m1), "H(m1) invalid");

                scheme.Adapt(r1_p, h1, r1, SP, mpk, msk, u1, MSP, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, SP, mpk, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, SP, mpk, m1), "Adapt(m1) invalid");

                scheme.Adapt(r1_p, h2, r2, SP, mpk, msk, u1, MSP, m2, m1);
                assertTrue(scheme.Check(h2, r1_p, SP, mpk, m1), "Adapt(m1) valid");
                assertFalse(scheme.Check(h2, r1_p, SP, mpk, m2), "Adapt(m2) invalid");

                scheme.Adapt(r1_p, h1, r1, SP, mpk, msk, u1, MSP, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, SP, mpk, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, SP, mpk, m1), "Adapt(m1) invalid");

                scheme.Adapt(r1_p, h2, r2, SP, mpk, msk, u1, MSP, m2, m1);
                assertTrue(scheme.Check(h2, r1_p, SP, mpk, m1), "Adapt(m1) valid");
                assertFalse(scheme.Check(h2, r1_p, SP, mpk, m2), "Adapt(m2) invalid");

                scheme.Adapt(r1_p, h2, r2, SP, mpk, msk, u2, MSP, m2, m1);
                assertFalse(scheme.Check(h2, r1_p, SP, mpk, m1), "policy false");
                assertFalse(scheme.Check(h2, r1_p, SP, mpk, m2), "policy false");
            }

            @DisplayName("test MCL impl")
            @ParameterizedTest(name = "test curve {0} k = {1}")
            @MethodSource("PBCHTest#GetMCLInvertkSmall")
            void MCLTest(curve.MCL curve, int k) {
                Func.MCLInit(curve);
                {
                    ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL scheme = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL();
                    ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.PublicParam SP = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.PublicParam();
                    ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.MasterPublicKey mpk = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.MasterPublicKey();
                    ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.MasterSecretKey msk = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.MasterSecretKey();
                    scheme.SetUp(mpk, msk, k);

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();

                    S1.attrs.add("A");
                    S1.attrs.add("DDDD");

                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.User u1 = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.User(k / 3);
                    scheme.AssignUser(u1, mpk, msk);
                    scheme.KeyGen(u1, SP, mpk, msk, S1);

                    ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.User u2 = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.User(u1, k / 2);
                    scheme.AssignUser(u2, mpk, msk);
                    scheme.KeyGen(u2, SP, mpk, msk, S2);

                    Fr m1 = new Fr();
                    Func.GetMCLZrRandomElement(m1);
                    Fr m2 = new Fr();
                    Func.GetMCLZrRandomElement(m2);

                    ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.HashValue h1 = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.HashValue();
                    ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.HashValue h2 = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.HashValue();
                    ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.Randomness r1 = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.Randomness();
                    ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.Randomness r2 = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.Randomness();
                    ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.Randomness r1_p = new ChameleonHash.PBCH.DEPRECATED.PCHBA_TLL_2020.MCL.Randomness();

                    scheme.Hash(h1, r1, SP, mpk, u1, MSP, m1);
                    assertTrue(scheme.Check(h1, r1, SP, mpk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, SP, mpk, m2), "H(m2) invalid");

                    scheme.Hash(h2, r2, SP, mpk, u2, MSP, m2);
                    assertTrue(scheme.Check(h2, r2, SP, mpk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, SP, mpk, m1), "H(m1) invalid");

                    scheme.Adapt(r1_p, h2, r2, SP, mpk, msk, u1, MSP, m2, m1);
                    assertTrue(scheme.Check(h2, r1_p, SP, mpk, m1), "Adapt(m1) valid");
                    assertFalse(scheme.Check(h2, r1_p, SP, mpk, m2), "Adapt(m2) invalid");

                    scheme.Adapt(r1_p, h1, r1, SP, mpk, msk, u1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, mpk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, SP, mpk, m1), "Adapt(m1) invalid");

                    scheme.Adapt(r1_p, h1, r1, SP, mpk, msk, u1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, mpk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, SP, mpk, m1), "Adapt(m1) invalid");

                    scheme.Adapt(r1_p, h2, r2, SP, mpk, msk, u1, MSP, m2, m1);
                    assertTrue(scheme.Check(h2, r1_p, SP, mpk, m1), "Adapt(m1) valid");
                    assertFalse(scheme.Check(h2, r1_p, SP, mpk, m2), "Adapt(m2) invalid");

                    scheme.Adapt(r1_p, h2, r2, SP, mpk, msk, u2, MSP, m2, m1);
                    assertFalse(scheme.Check(h2, r1_p, SP, mpk, m1), "policy false");
                    assertFalse(scheme.Check(h2, r1_p, SP, mpk, m2), "policy false");
                }
                {
                    MCL_swap scheme = new MCL_swap();
                    MCL_swap.PublicParam SP = new MCL_swap.PublicParam();
                    MCL_swap.MasterPublicKey mpk = new MCL_swap.MasterPublicKey();
                    MCL_swap.MasterSecretKey msk = new MCL_swap.MasterSecretKey();
                    scheme.SetUp(mpk, msk, k);

                    base.LSSS.MCL LSSS = new base.LSSS.MCL();
                    base.LSSS.MCL.Matrix MSP = new base.LSSS.MCL.Matrix();
                    BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                    LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                    BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                    BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();

                    S1.attrs.add("A");
                    S1.attrs.add("DDDD");

                    S2.attrs.add("BB");
                    S2.attrs.add("CCC");

                    MCL_swap.User u1 = new MCL_swap.User(k / 3);
                    scheme.AssignUser(u1, mpk, msk);
                    scheme.KeyGen(u1, SP, mpk, msk, S1);

                    MCL_swap.User u2 = new MCL_swap.User(u1, k / 2);
                    scheme.AssignUser(u2, mpk, msk);
                    scheme.KeyGen(u2, SP, mpk, msk, S2);

                    Fr m1 = new Fr();
                    Func.GetMCLZrRandomElement(m1);
                    Fr m2 = new Fr();
                    Func.GetMCLZrRandomElement(m2);

                    MCL_swap.HashValue h1 = new MCL_swap.HashValue();
                    MCL_swap.HashValue h2 = new MCL_swap.HashValue();
                    MCL_swap.Randomness r1 = new MCL_swap.Randomness();
                    MCL_swap.Randomness r2 = new MCL_swap.Randomness();
                    MCL_swap.Randomness r1_p = new MCL_swap.Randomness();

                    scheme.Hash(h1, r1, SP, mpk, u1, MSP, m1);
                    assertTrue(scheme.Check(h1, r1, SP, mpk, m1), "H(m1) valid");
                    assertFalse(scheme.Check(h1, r1, SP, mpk, m2), "H(m2) invalid");

                    scheme.Hash(h2, r2, SP, mpk, u2, MSP, m2);
                    assertTrue(scheme.Check(h2, r2, SP, mpk, m2), "H(m2) valid");
                    assertFalse(scheme.Check(h2, r2, SP, mpk, m1), "H(m1) invalid");

                    scheme.Adapt(r1_p, h2, r2, SP, mpk, msk, u1, MSP, m2, m1);
                    assertTrue(scheme.Check(h2, r1_p, SP, mpk, m1), "Adapt(m1) valid");
                    assertFalse(scheme.Check(h2, r1_p, SP, mpk, m2), "Adapt(m2) invalid");

                    scheme.Adapt(r1_p, h1, r1, SP, mpk, msk, u1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, mpk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, SP, mpk, m1), "Adapt(m1) invalid");

                    scheme.Adapt(r1_p, h1, r1, SP, mpk, msk, u1, MSP, m1, m2);
                    assertTrue(scheme.Check(h1, r1_p, SP, mpk, m2), "Adapt(m2) valid");
                    assertFalse(scheme.Check(h1, r1_p, SP, mpk, m1), "Adapt(m1) invalid");

                    scheme.Adapt(r1_p, h2, r2, SP, mpk, msk, u1, MSP, m2, m1);
                    assertTrue(scheme.Check(h2, r1_p, SP, mpk, m1), "Adapt(m1) valid");
                    assertFalse(scheme.Check(h2, r1_p, SP, mpk, m2), "Adapt(m2) invalid");

                    scheme.Adapt(r1_p, h2, r2, SP, mpk, msk, u2, MSP, m2, m1);
                    assertFalse(scheme.Check(h2, r1_p, SP, mpk, m1), "policy false");
                    assertFalse(scheme.Check(h2, r1_p, SP, mpk, m2), "policy false");
                }
            }
        }
    }
}
