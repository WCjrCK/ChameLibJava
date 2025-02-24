import base.BinaryTree.PBC;
import it.unisa.dia.gas.jpbc.Element;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import utils.BooleanFormulaParser;

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

    public static Stream<Arguments> GetPBCInvertkn() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a ->
                Stream.of(128, 256, 512).flatMap(b ->
                        Stream.of(16, 32, 64).flatMap(c ->
                                Stream.of(Arguments.of(a, false, b, c), Arguments.of(a, true, b, c))
                        )
                )
        );
    }

    @BeforeEach
    void initTest() {
        InitialLib();
    }

    @DisplayName("test paper 《Fine-Grained and Controlled Rewriting in Blockchains Chameleon-Hashing Gone Attribute-Based》")
    @Nested
    class FineGrainedAndControlledRewritingInBlockchainsChameleonHashingGoneAttributeBasedTest {
        @DisplayName("test PCH_DSS_2019")
        @Nested
        class PCH_DSS_2019_Test {
            @DisplayName("test PBC impl")
            @ParameterizedTest(name = "test curve {0} swap_G1G2 {1} k = {2}")
            @MethodSource("PBCHTest#GetPBCInvertk")
            void JPBCTest(curve.PBC curve, boolean swap_G1G2, int k) {
                scheme.PBCH.PCH_DSS_2019.PBC scheme = new scheme.PBCH.PCH_DSS_2019.PBC(k);
                scheme.PBCH.PCH_DSS_2019.PBC.PublicParam pp_PCH = new scheme.PBCH.PCH_DSS_2019.PBC.PublicParam(curve, swap_G1G2);
                scheme.PBCH.PCH_DSS_2019.PBC.MasterPublicKey pk_PCH = new scheme.PBCH.PCH_DSS_2019.PBC.MasterPublicKey();
                scheme.PBCH.PCH_DSS_2019.PBC.MasterSecretKey sk_PCH = new scheme.PBCH.PCH_DSS_2019.PBC.MasterSecretKey();
                scheme.SetUp(pk_PCH, sk_PCH, pp_PCH);

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(pp_PCH.GP.Zr);
                BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

                BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
                BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();

                S1.attrs.add("A");
                S1.attrs.add("DDDD");

                S2.attrs.add("BB");
                S2.attrs.add("CCC");

                scheme.PBCH.PCH_DSS_2019.PBC.SecretKey sk1 = new scheme.PBCH.PCH_DSS_2019.PBC.SecretKey();
                scheme.KeyGen(sk1, pp_PCH, pk_PCH, sk_PCH, S1);

                scheme.PBCH.PCH_DSS_2019.PBC.SecretKey sk2 = new scheme.PBCH.PCH_DSS_2019.PBC.SecretKey();
                scheme.KeyGen(sk2, pp_PCH, pk_PCH, sk_PCH, S2);

                String m1 = "WCjrCK";
                String m2 = "123";

                scheme.PBCH.PCH_DSS_2019.PBC.HashValue h1 = new scheme.PBCH.PCH_DSS_2019.PBC.HashValue();
                scheme.PBCH.PCH_DSS_2019.PBC.HashValue h2 = new scheme.PBCH.PCH_DSS_2019.PBC.HashValue();
                scheme.PBCH.PCH_DSS_2019.PBC.Randomness r1 = new scheme.PBCH.PCH_DSS_2019.PBC.Randomness();
                scheme.PBCH.PCH_DSS_2019.PBC.Randomness r2 = new scheme.PBCH.PCH_DSS_2019.PBC.Randomness();
                scheme.PBCH.PCH_DSS_2019.PBC.Randomness r1_p = new scheme.PBCH.PCH_DSS_2019.PBC.Randomness();

                scheme.Hash(h1, r1, pp_PCH, pk_PCH, MSP, m1);
                assertTrue(scheme.Check(h1, r1, pk_PCH, m1), "H(m1) valid");
                assertFalse(scheme.Check(h1, r1, pk_PCH, m2), "H(m2) invalid");

                scheme.Hash(h2, r2, pp_PCH, pk_PCH, MSP, m2);
                assertTrue(scheme.Check(h2, r2, pk_PCH, m2), "H(m2) valid");
                assertFalse(scheme.Check(h2, r2, pk_PCH, m1), "H(m1) invalid");

                scheme.Adapt(r1_p, h1, r1, pp_PCH, pk_PCH, MSP, sk1, m1, m2);
                assertTrue(scheme.Check(h1, r1_p, pk_PCH, m2), "Adapt(m2) valid");
                assertFalse(scheme.Check(h1, r1_p, pk_PCH, m1), "Adapt(m1) invalid");
            }
        }
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
                scheme.PBCH.MAPCH_ZLW_2021.PBC scheme = new scheme.PBCH.MAPCH_ZLW_2021.PBC(lambda);
                scheme.PBCH.MAPCH_ZLW_2021.PBC.PublicParam SP = new scheme.PBCH.MAPCH_ZLW_2021.PBC.PublicParam();
                scheme.SetUp(SP, curve);

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(SP.GP.Zr);
                BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                LSSS.GenLSSSMatrices(MSP, pl, "(A|FF)&(DDDD|(BB&CCC))");

                String GID1 = "WCjrCK";
                String GID2 = "gid2";
                scheme.PBCH.MAPCH_ZLW_2021.PBC.SecretKey SK1 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.SecretKey();
                scheme.PBCH.MAPCH_ZLW_2021.PBC.SecretKey SK2 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.SecretKey();

                scheme.PBCH.MAPCH_ZLW_2021.PBC.Authority[] auths = new scheme.PBCH.MAPCH_ZLW_2021.PBC.Authority[auth_num];
                for (int i = 0; i < auth_num; ++i)
                    auths[i] = new scheme.PBCH.MAPCH_ZLW_2021.PBC.Authority("auth_" + i, SP);

                auths[0].MA_ABE_Auth.control_attr.add("A");
                auths[1].MA_ABE_Auth.control_attr.add("BB");
                auths[2].MA_ABE_Auth.control_attr.add("CCC");
                auths[3].MA_ABE_Auth.control_attr.add("DDDD");
                auths[4].MA_ABE_Auth.control_attr.add("E");
                auths[5].MA_ABE_Auth.control_attr.add("FF");

                scheme.PBCH.MAPCH_ZLW_2021.PBC.PublicKeyGroup PKG = new scheme.PBCH.MAPCH_ZLW_2021.PBC.PublicKeyGroup();
                for (int i = 0; i < auth_num; ++i) scheme.AuthSetup(auths[i]);
                for (int i = 0; i < auth_num; ++i) PKG.AddPK(auths[i]);

                scheme.PBCH.MAPCH_ZLW_2021.PBC.SecretKeyGroup SKG1 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.SecretKeyGroup();
                scheme.PBCH.MAPCH_ZLW_2021.PBC.SecretKeyGroup SKG3 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.SecretKeyGroup();
                scheme.KeyGen(auths[0], SK1, GID1, "A");
                SKG1.AddSK(SK1);
                SKG3.AddSK(SK1);
                scheme.KeyGen(auths[3], SK1, GID1, "DDDD");
                SKG1.AddSK(SK1);
                scheme.KeyGen(auths[4], SK1, GID1, "E");
                SKG1.AddSK(SK1);

                scheme.PBCH.MAPCH_ZLW_2021.PBC.SecretKeyGroup SKG2 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.SecretKeyGroup();
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

                scheme.PBCH.MAPCH_ZLW_2021.PBC.HashValue h1 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.HashValue();
                scheme.PBCH.MAPCH_ZLW_2021.PBC.HashValue h2 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.HashValue();

                scheme.PBCH.MAPCH_ZLW_2021.PBC.Randomness r1 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.Randomness();
                scheme.PBCH.MAPCH_ZLW_2021.PBC.Randomness r2 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.Randomness();
                scheme.PBCH.MAPCH_ZLW_2021.PBC.Randomness r1_p = new scheme.PBCH.MAPCH_ZLW_2021.PBC.Randomness();

                scheme.Hash(h1, r1, PKG, MSP, m1);
                scheme.Hash(h2, r2, PKG, MSP, m2);
                assertTrue(scheme.Check(h1, r1, PKG, m1), "H(m1) valid");
                assertFalse(scheme.Check(h1, r1, PKG, m2), "H(m2) invalid");
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
                scheme.PBCH.DPCH_MXN_2022.PBC scheme = new scheme.PBCH.DPCH_MXN_2022.PBC(lambda);
                scheme.PBCH.DPCH_MXN_2022.PBC.PublicParam SP = new scheme.PBCH.DPCH_MXN_2022.PBC.PublicParam();
                scheme.PBCH.DPCH_MXN_2022.PBC.MasterPublicKey MPK = new scheme.PBCH.DPCH_MXN_2022.PBC.MasterPublicKey();
                scheme.PBCH.DPCH_MXN_2022.PBC.MasterSecretKey MSK = new scheme.PBCH.DPCH_MXN_2022.PBC.MasterSecretKey();
                scheme.SetUp(SP, MPK, MSK, curve);

                base.LSSS.PBC LSSS = new base.LSSS.PBC();
                base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(SP.GP_MA_ABE.Zr);
                BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
                LSSS.GenLSSSMatrices(MSP, pl, "(A|FF)&(DDDD|(BB&CCC))");

                String GID1 = "WCjrCK_gid";
                String GID2 = "gid2";

                scheme.PBCH.DPCH_MXN_2022.PBC.Modifier mod1 = new scheme.PBCH.DPCH_MXN_2022.PBC.Modifier(GID1);
                scheme.PBCH.DPCH_MXN_2022.PBC.Modifier mod2 = new scheme.PBCH.DPCH_MXN_2022.PBC.Modifier(GID2);

                scheme.ModSetup(mod1, SP, MSK);
                scheme.ModSetup(mod2, SP, MSK);

                scheme.PBCH.DPCH_MXN_2022.PBC.Authority[] auths = new scheme.PBCH.DPCH_MXN_2022.PBC.Authority[auth_num];
                for (int i = 0; i < auth_num; ++i) {
                    auths[i] = new scheme.PBCH.DPCH_MXN_2022.PBC.Authority("auth_" + i);
                    scheme.AuthSetup(auths[i], SP);
                }

                auths[0].MA_ABE_Auth.control_attr.add("A");
                auths[1].MA_ABE_Auth.control_attr.add("BB");
                auths[2].MA_ABE_Auth.control_attr.add("CCC");
                auths[3].MA_ABE_Auth.control_attr.add("DDDD");
                auths[4].MA_ABE_Auth.control_attr.add("E");
                auths[5].MA_ABE_Auth.control_attr.add("FF");

                scheme.PBCH.DPCH_MXN_2022.PBC.PublicKeyGroup PKG = new scheme.PBCH.DPCH_MXN_2022.PBC.PublicKeyGroup();
                for (int i = 0; i < auth_num; ++i) scheme.AuthSetup(auths[i], SP);
                for (int i = 0; i < auth_num; ++i) PKG.AddPK(auths[i]);

                scheme.PBCH.DPCH_MXN_2022.PBC.SecretKeyGroup SKG1 = new scheme.PBCH.DPCH_MXN_2022.PBC.SecretKeyGroup();
                scheme.PBCH.DPCH_MXN_2022.PBC.SecretKeyGroup SKG3 = new scheme.PBCH.DPCH_MXN_2022.PBC.SecretKeyGroup();
                scheme.ModKeyGen(mod1, SP, MPK, auths[0], "A");
                SKG1.AddSK(mod1);
                SKG3.AddSK(mod1);
                scheme.ModKeyGen(mod1, SP, MPK, auths[3], "DDDD");
                SKG1.AddSK(mod1);
                scheme.ModKeyGen(mod1, SP, MPK, auths[4], "E");
                SKG1.AddSK(mod1);

                scheme.PBCH.DPCH_MXN_2022.PBC.SecretKeyGroup SKG2 = new scheme.PBCH.DPCH_MXN_2022.PBC.SecretKeyGroup();
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

                scheme.PBCH.DPCH_MXN_2022.PBC.HashValue h1 = new scheme.PBCH.DPCH_MXN_2022.PBC.HashValue();
                scheme.PBCH.DPCH_MXN_2022.PBC.HashValue h2 = new scheme.PBCH.DPCH_MXN_2022.PBC.HashValue();

                scheme.PBCH.DPCH_MXN_2022.PBC.Randomness r1 = new scheme.PBCH.DPCH_MXN_2022.PBC.Randomness();
                scheme.PBCH.DPCH_MXN_2022.PBC.Randomness r2 = new scheme.PBCH.DPCH_MXN_2022.PBC.Randomness();
                scheme.PBCH.DPCH_MXN_2022.PBC.Randomness r1_p = new scheme.PBCH.DPCH_MXN_2022.PBC.Randomness();

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
                scheme.PBCH.RPCH_XNM_2021.PBC scheme = new scheme.PBCH.RPCH_XNM_2021.PBC(k);
                scheme.PBCH.RPCH_XNM_2021.PBC.PublicParam SP = new scheme.PBCH.RPCH_XNM_2021.PBC.PublicParam(curve, swap_G1G2);
                scheme.PBCH.RPCH_XNM_2021.PBC.MasterPublicKey mpk = new scheme.PBCH.RPCH_XNM_2021.PBC.MasterPublicKey();
                scheme.PBCH.RPCH_XNM_2021.PBC.MasterSecretKey msk = new scheme.PBCH.RPCH_XNM_2021.PBC.MasterSecretKey();
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
                scheme.PBCH.RPCH_XNM_2021.PBC.SecretKey sk1 = new scheme.PBCH.RPCH_XNM_2021.PBC.SecretKey();
                scheme.KeyGen(sk1, BT, SP, mpk, msk, S1, id1);

                Element id2 = SP.GP.GetZrElement();
                scheme.PBCH.RPCH_XNM_2021.PBC.SecretKey sk2 = new scheme.PBCH.RPCH_XNM_2021.PBC.SecretKey();
                scheme.KeyGen(sk2, BT, SP, mpk, msk, S2, id2);

                scheme.PBCH.RPCH_XNM_2021.PBC.SecretKey sk3 = new scheme.PBCH.RPCH_XNM_2021.PBC.SecretKey();
                scheme.KeyGen(sk3, BT, SP, mpk, msk, S3, id1);

                scheme.Revoke(rl, id1, 10);
                scheme.Revoke(rl, id2, 100);

                scheme.PBCH.RPCH_XNM_2021.PBC.UpdateKey ku1 = new scheme.PBCH.RPCH_XNM_2021.PBC.UpdateKey();
                scheme.UpdateKeyGen(ku1, SP, mpk, BT, rl, 5);

                scheme.PBCH.RPCH_XNM_2021.PBC.UpdateKey ku2 = new scheme.PBCH.RPCH_XNM_2021.PBC.UpdateKey();
                scheme.UpdateKeyGen(ku2, SP, mpk, BT, rl, 50);

                scheme.PBCH.RPCH_XNM_2021.PBC.DecryptKey dk_1_1 = new scheme.PBCH.RPCH_XNM_2021.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_1_1, SP, mpk, sk1, ku1, BT, rl);

                scheme.PBCH.RPCH_XNM_2021.PBC.DecryptKey dk_1_2 = new scheme.PBCH.RPCH_XNM_2021.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_1_2, SP, mpk, sk1, ku2, BT, rl);

                scheme.PBCH.RPCH_XNM_2021.PBC.DecryptKey dk_2_1 = new scheme.PBCH.RPCH_XNM_2021.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_2_1, SP, mpk, sk2, ku1, BT, rl);

                scheme.PBCH.RPCH_XNM_2021.PBC.DecryptKey dk_2_2 = new scheme.PBCH.RPCH_XNM_2021.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_2_2, SP, mpk, sk2, ku2, BT, rl);

                scheme.PBCH.RPCH_XNM_2021.PBC.DecryptKey dk_3_1 = new scheme.PBCH.RPCH_XNM_2021.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_3_1, SP, mpk, sk3, ku1, BT, rl);

                scheme.PBCH.RPCH_XNM_2021.PBC.DecryptKey dk_3_2 = new scheme.PBCH.RPCH_XNM_2021.PBC.DecryptKey();
                scheme.DecryptKeyGen(dk_3_2, SP, mpk, sk3, ku2, BT, rl);

                String m1 = "WCjrCK";
                String m2 = "123";

                scheme.PBCH.RPCH_XNM_2021.PBC.HashValue h1 = new scheme.PBCH.RPCH_XNM_2021.PBC.HashValue();
                scheme.PBCH.RPCH_XNM_2021.PBC.HashValue h2 = new scheme.PBCH.RPCH_XNM_2021.PBC.HashValue();
                scheme.PBCH.RPCH_XNM_2021.PBC.Randomness r1 = new scheme.PBCH.RPCH_XNM_2021.PBC.Randomness();
                scheme.PBCH.RPCH_XNM_2021.PBC.Randomness r2 = new scheme.PBCH.RPCH_XNM_2021.PBC.Randomness();
                scheme.PBCH.RPCH_XNM_2021.PBC.Randomness r1_p = new scheme.PBCH.RPCH_XNM_2021.PBC.Randomness();

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
