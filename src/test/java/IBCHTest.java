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
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.HashValue h = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.HashValue();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness r = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness();
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness r_p = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.Randomness();

                Element m,m_p;  // message
                String ID = "identity string ID";
                String L = "customozed identity L";
                m = ch.GetZnElement();
                m_p = ch.GetZnElement();

                ch.SetUp(pp, msk);

                ch.Extract(td, ID, msk);

                ch.Hash(h, r, ID, L, m, pp);

                assertTrue(ch.Check(h, r, L, m, td), "Check failed");

                ch.Adapt(r_p, m_p, h, r, L, m, td);

                assertTrue(ch.Check(h, r_p, L, m_p, td), "Verify failed");
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
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.HashValue h = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.HashValue();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness r = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness();
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness r_p = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC.Randomness();

                Element m,m_p;  // message
                Element ID;

                m = ch.GetZnElement();
                m_p = ch.GetZnElement();
                ID = ch.GetZnElement();

                ch.SetUp(pp, msk);

                ch.KeyGen(td, ID, msk, pp);

                ch.Hash(h, r, ID, m, pp);

                assertTrue(ch.Check(h, r, ID, m, pp), "Check failed");

                ch.Adapt(r_p, h, m, r, m_p, td);

                assertTrue(ch.Check(h, r_p, ID, m_p, pp), "Verify failed");
            }
        }
    }
}
