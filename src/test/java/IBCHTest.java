import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;


public class IBCHTest { 
    @BeforeAll
    static void initTest() {
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
    }

    @DisplayName("test paper 《Identity-based chameleon hashing and signatures without key exposure》")
    @Nested
    class IdentityBasedChameleonHashingAndSignaturesWithoutKeyExposureTest{
        @DisplayName("test IB_CH_KEF_CZS_2014")
        @Nested
        class IB_CH_KEF_CZS_2014_Test{
            @DisplayName("test pbc impl")
            @ParameterizedTest(name = "test curve {0}")
            @EnumSource(names = {"A", "A1", "E"})
            void JPBCTest(curve.PBC curve) {
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC ch = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC(curve);       
                  
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.PublicParam pp = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.PublicParam();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.MasterSecrtKey msk = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.MasterSecrtKey();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Trapdoor td = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Trapdoor();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.HashValue h1 = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.HashValue();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.HashValue h2 = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.HashValue();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness r1 = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness r2 = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness r1_p = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness();

                Element m,m_p;  // message
                String ID = "identity string ID";
                String L = "customozed identity L";
                m = ch.GetZnElement();
                m_p = ch.GetZnElement();

                ch.SetUp(pp, msk);

                ch.Extract(td, ID, msk);

                ch.Hash(h1, r1, ID, L, m, pp);
                ch.Hash(h2, r2, ID, L, m_p, pp);
                assertTrue(ch.Check(h1, r1, L, m, td), "H(m) valid");
                assertTrue(ch.Check(h2, r2, L, m_p, td), "H(m_p) valid");
                assertFalse(ch.Check(h1, r1, L, m_p, td), "not H(m)");
                assertFalse(ch.Check(h2, r2, L, m, td), "not H(m_p)");

                ch.Adapt(r1_p, m_p, h1, r1, L, m, td);

                assertTrue(ch.Check(h1, r1_p, L, m_p, td), "adapted m_p valid");
                assertFalse(ch.Check(h1, r1_p, L, m, td), "not adapted m");
            }
        }
    }


    @DisplayName("test paper 《Efficient Identity-Based Chameleon Hash For Mobile Devices》")
    @Nested
    class EfficientIdentityBasedChameleonHashForMobileDevicesTest{
        @DisplayName("test IB_CH_MD_LSX_2022")
        @Nested
        class IB_CH_MD_LSX_2022_Test{
            @DisplayName("test pbc impl")
            @ParameterizedTest(name = "test curve {0}")
            @EnumSource(names = {"A", "A1", "E"})
            void JPBCTest(curve.PBC curve) {
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC ch = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC(curve);
                   
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.PublicParam pp = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.PublicParam();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.MasterSecrtKey msk = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.MasterSecrtKey();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Trapdoor td = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Trapdoor();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.HashValue h1 = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.HashValue();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.HashValue h2 = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.HashValue();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness r1 = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness r2 = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness r1_p = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness();

                Element m,m_p;  // message
                Element ID;

                m = ch.GetZnElement();
                m_p = ch.GetZnElement();
                ID = ch.GetZnElement();

                ch.SetUp(pp, msk);

                ch.KeyGen(td, ID, msk, pp);

                ch.Hash(h1, r1, ID, m, pp);
                ch.Hash(h2, r2, ID, m_p, pp);
                assertTrue(ch.Check(h1, r1, ID, m, pp), "H(m) valid");
                assertTrue(ch.Check(h2, r2, ID, m_p, pp), "H(m_p) valid");
                assertFalse(ch.Check(h1, r1, ID, m_p, pp), "not H(m)");
                assertFalse(ch.Check(h2, r2, ID, m, pp), "not H(m_p)");

                ch.Adapt(r1_p, h1, m, r1, m_p, td);
                assertTrue(ch.Check(h1, r1_p, ID, m_p, pp), "adapted m_p valid");
                assertFalse(ch.Check(h1, r1_p, ID, m, pp), "not adapted m");
            }
        }
    }
}
