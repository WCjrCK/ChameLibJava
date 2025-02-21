import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import utils.BooleanFormulaParser;

import java.math.BigInteger;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static utils.Func.InitialLib;

public class PBCHTest {
    public static Stream<Arguments> GetPBCSymmAuth() {
        return Stream.of(curve.PBC.A, curve.PBC.A1, curve.PBC.E).flatMap(a ->
                Stream.of(16, 32, 64).flatMap(b ->
                        Stream.of(64, 128, 256).flatMap(c -> Stream.of(Arguments.of(a, b, c)))));
    }

    @BeforeAll
    static void initTest() {
        InitialLib();
    }

    @DisplayName("test paper 《Fine-Grained and Controlled Rewriting in Blockchains Chameleon-Hashing Gone Attribute-Based》")
    @Nested
    class FineGrainedAndControlledRewritingInBlockchainsChameleonHashingGoneAttributeBasedTest {
        @DisplayName("test PBC impl")
        @ParameterizedTest(name = "test curve {0} swap_G1G2 {1}")
        @MethodSource("ABETest#GetPBCInvert")
        void JPBCTest(curve.PBC curve, boolean swap_G1G2) {
            Random rand = new Random();
            scheme.PBCH.PCH_DSS_2019.PBC scheme = new scheme.PBCH.PCH_DSS_2019.PBC(128);
            scheme.PBCH.PCH_DSS_2019.PBC.PublicParam pk_PCH = new scheme.PBCH.PCH_DSS_2019.PBC.PublicParam();
            scheme.PBCH.PCH_DSS_2019.PBC.MasterSecretKey sk_PCH = new scheme.PBCH.PCH_DSS_2019.PBC.MasterSecretKey();
            scheme.SetUp(pk_PCH, sk_PCH, curve, swap_G1G2);

            base.LSSS.PBC LSSS = new base.LSSS.PBC();
            base.LSSS.PBC.Matrix MSP = new base.LSSS.PBC.Matrix(pk_PCH.mpk_ABE.Zr);
            BooleanFormulaParser.PolicyList pl = new BooleanFormulaParser.PolicyList();
            LSSS.GenLSSSMatrices(MSP, pl, "A&(DDDD|(BB&CCC))");

            BooleanFormulaParser.AttributeList S1 = new BooleanFormulaParser.AttributeList();
            BooleanFormulaParser.AttributeList S2 = new BooleanFormulaParser.AttributeList();

            S1.attrs.add("A");
            S1.attrs.add("DDDD");

            S2.attrs.add("BB");
            S2.attrs.add("CCC");

            scheme.PBCH.PCH_DSS_2019.PBC.SecretKey sk1 = new scheme.PBCH.PCH_DSS_2019.PBC.SecretKey();
            scheme.PBCH.PCH_DSS_2019.PBC.SecretKey sk2 = new scheme.PBCH.PCH_DSS_2019.PBC.SecretKey();
            scheme.KeyGen(sk1, pk_PCH, sk_PCH, S1);
            scheme.KeyGen(sk2, pk_PCH, sk_PCH, S2);

            BigInteger m1 = new BigInteger(512, rand);
            BigInteger m2 = new BigInteger(512, rand);

            scheme.PBCH.PCH_DSS_2019.PBC.HashValue h1 = new scheme.PBCH.PCH_DSS_2019.PBC.HashValue();
            scheme.PBCH.PCH_DSS_2019.PBC.HashValue h2 = new scheme.PBCH.PCH_DSS_2019.PBC.HashValue();
            scheme.PBCH.PCH_DSS_2019.PBC.Randomness r1 = new scheme.PBCH.PCH_DSS_2019.PBC.Randomness();
            scheme.PBCH.PCH_DSS_2019.PBC.Randomness r2 = new scheme.PBCH.PCH_DSS_2019.PBC.Randomness();
            scheme.PBCH.PCH_DSS_2019.PBC.Randomness r1_p = new scheme.PBCH.PCH_DSS_2019.PBC.Randomness();

            scheme.Hash(h1, r1, pk_PCH, MSP, m1);
            scheme.Hash(h2, r2, pk_PCH, MSP, m2);
            assertTrue(scheme.Check(h1, r1, pk_PCH, m1), "H(m1) valid");
            assertFalse(scheme.Check(h1, r1, pk_PCH, m2), "H(m2) invalid");

            scheme.Adapt(r1_p, h1, r1, pk_PCH, MSP, sk1, m1, m2);
            assertTrue(scheme.Check(h1, r1_p, pk_PCH, m2), "Adapt(m2) valid");
            assertFalse(scheme.Check(h1, r1_p, pk_PCH, m1), "Adapt(m1) invalid");
        }
    }

    @DisplayName("test paper 《Redactable Transactions in Consortium Blockchain Controlled by Multi-authority CP-ABE》")
    @Nested
    class RedactableTransactionsInConsortiumBlockchainControlledByMultiAuthorityCPABETest {
        @DisplayName("test PBC impl")
        @ParameterizedTest(name = "test curve {0} author number {1} lambda = {2}")
        @MethodSource("PBCHTest#GetPBCSymmAuth")
        void JPBCTest(curve.PBC curve, int auth_num, int lambda) {
            Random rand = new Random();
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
            for(int i = 0;i < auth_num;++i) auths[i] = new scheme.PBCH.MAPCH_ZLW_2021.PBC.Authority("auth_" + i, SP);

            auths[0].MA_ABE_Auth.control_attr.add("A");
            auths[1].MA_ABE_Auth.control_attr.add("BB");
            auths[2].MA_ABE_Auth.control_attr.add("CCC");
            auths[3].MA_ABE_Auth.control_attr.add("DDDD");
            auths[4].MA_ABE_Auth.control_attr.add("E");
            auths[5].MA_ABE_Auth.control_attr.add("FF");

            scheme.PBCH.MAPCH_ZLW_2021.PBC.PublicKeyGroup PKG = new scheme.PBCH.MAPCH_ZLW_2021.PBC.PublicKeyGroup();
            for(int i = 0;i < auth_num;++i) scheme.AuthSetup(auths[i]);
            for(int i = 0;i < auth_num;++i) PKG.AddPK(auths[i]);

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

            BigInteger m1 = new BigInteger(lambda, rand);
            BigInteger m2 = new BigInteger(lambda, rand);

            scheme.PBCH.MAPCH_ZLW_2021.PBC.HashValue h1 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.HashValue();
            scheme.PBCH.MAPCH_ZLW_2021.PBC.HashValue h2 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.HashValue();

            scheme.PBCH.MAPCH_ZLW_2021.PBC.Randomness r1 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.Randomness();
            scheme.PBCH.MAPCH_ZLW_2021.PBC.Randomness r2 = new scheme.PBCH.MAPCH_ZLW_2021.PBC.Randomness();
            scheme.PBCH.MAPCH_ZLW_2021.PBC.Randomness r1_p = new scheme.PBCH.MAPCH_ZLW_2021.PBC.Randomness();

            scheme.Hash(h1, r1, PKG, SKG1, MSP, m1);
            scheme.Hash(h2, r2, PKG, MSP, m2);
            assertTrue(scheme.Check(h1, r1, PKG, m1), "H(m1) valid");
            assertFalse(scheme.Check(h1, r1, PKG, m2), "H(m2) invalid");
            assertTrue(scheme.Check(h2, r2, PKG, m2), "H(m2) valid");
            assertFalse(scheme.Check(h2, r2, PKG, m1), "H(m1) invalid");
//
            scheme.Adapt(r1_p, h1, r1, PKG, SKG1, MSP, m1, m2);
            assertTrue(scheme.Check(h1, r1_p, PKG, m2), "Adapt(m2) valid");
            assertFalse(scheme.Check(h1, r1_p, PKG, m1), "Adapt(m1) invalid");
        }
    }
}
