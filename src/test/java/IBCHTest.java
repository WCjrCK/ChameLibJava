import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.EnumSet;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.IB_CH_KEF_CZS_2014_h;
import scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.IB_CH_KEF_CZS_2014_msk;
import scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.IB_CH_KEF_CZS_2014_pp;
import scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.IB_CH_KEF_CZS_2014_r;
import scheme.IBCH.IB_CH_KEF_CZS_2014.PBC.IB_CH_KEF_CZS_2014_td;
import scheme.IBCH.IB_CH_MD_LSX_2022.PBC.IB_CH_MD_LSX_2022_h;
import scheme.IBCH.IB_CH_MD_LSX_2022.PBC.IB_CH_MD_LSX_2022_msk;
import scheme.IBCH.IB_CH_MD_LSX_2022.PBC.IB_CH_MD_LSX_2022_pp;
import scheme.IBCH.IB_CH_MD_LSX_2022.PBC.IB_CH_MD_LSX_2022_r;
import scheme.IBCH.IB_CH_MD_LSX_2022.PBC.IB_CH_MD_LSX_2022_td;
import utils.Logger;


public class IBCHTest {
    public static Stream<Arguments> GetPBC() {
        return EnumSet.allOf(curve.PBC.class).stream().flatMap(a -> Stream.of(Arguments.of(a, 0), Arguments.of(a, 1)));
    }
 
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
            @ParameterizedTest(name = "test curve {0}, reverse {1}")
            @MethodSource("IBCHTest#GetPBC")
            void JPBCTest(curve.PBC curve, int reverse) {
                scheme.IBCH.IB_CH_KEF_CZS_2014.PBC ch;
                if(reverse == 0) {
                    ch = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC(curve, Group.G1, Group.G2);
                }else{
                    ch = new scheme.IBCH.IB_CH_KEF_CZS_2014.PBC(curve, Group.G2, Group.G1);
                }                
                
                            
                IB_CH_KEF_CZS_2014_pp pp = new IB_CH_KEF_CZS_2014_pp();
                IB_CH_KEF_CZS_2014_msk msk = new IB_CH_KEF_CZS_2014_msk();
                IB_CH_KEF_CZS_2014_td td = new IB_CH_KEF_CZS_2014_td();
                IB_CH_KEF_CZS_2014_h h = new IB_CH_KEF_CZS_2014_h();
                IB_CH_KEF_CZS_2014_r r = new IB_CH_KEF_CZS_2014_r();
                IB_CH_KEF_CZS_2014_r r_p = new IB_CH_KEF_CZS_2014_r();

                Element m,m_p;  // message
                String ID = "identity string ID";
                String L = "customozed identity L";
                m = ch.GetRandomZnElement();
                m_p = ch.GetRandomZnElement();


                ch.SetUp(pp, msk, td, h, r, r_p);
                pp.print();

                ch.Extract(td, ID, msk);
                td.print();


                ch.Hash(h, r, ID, L, m, pp);
                h.print();
                r.print();


                assertTrue(ch.Check(h, r, L, m, td), "Check failed");


                ch.Adapt(r_p, m_p, h, r, L, m, td);
                r_p.print();


                assertTrue(ch.Verify(h, r_p, L, m_p, td), "Verify failed");
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
            @ParameterizedTest(name = "test curve {0}, reverse {1}")
            @MethodSource("IBCHTest#GetPBC")
            void JPBCTest(curve.PBC curve, int reverse) {
                scheme.IBCH.IB_CH_MD_LSX_2022.PBC ch;
                if(reverse == 0) {
                    ch = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC(curve, Group.G1, Group.G2);
                }else{
                    ch = new scheme.IBCH.IB_CH_MD_LSX_2022.PBC(curve, Group.G2, Group.G1);
                }           

                IB_CH_MD_LSX_2022_pp pp = new IB_CH_MD_LSX_2022_pp();
                IB_CH_MD_LSX_2022_msk msk = new IB_CH_MD_LSX_2022_msk();
                IB_CH_MD_LSX_2022_td td = new IB_CH_MD_LSX_2022_td();
                IB_CH_MD_LSX_2022_h h = new IB_CH_MD_LSX_2022_h();
                IB_CH_MD_LSX_2022_r r = new IB_CH_MD_LSX_2022_r();
                IB_CH_MD_LSX_2022_r r_p = new IB_CH_MD_LSX_2022_r();

                Element m,m_p;  // message
                Element ID;

                m = ch.GetRandomZnElement();
                m_p = ch.GetRandomZnElement();
                ID = ch.GetRandomZnElement();

                ch.SetUp(pp, msk, td, h, r, r_p);
                pp.print();
                msk.print();

                Logger.Print("ID", ID);
                ch.KeyGen(td, ID, msk, pp);
                td.print();

                Logger.Print("m", m);
                ch.Hash(h, r, ID, m, pp);
                h.print();
                r.print();

                assertTrue(ch.Check(h, r, ID, m, pp), "Check failed");

                Logger.Print("m_p", m_p);
                ch.Adapt(r_p, h, m, r, m_p, td);
                r_p.print();

                assertTrue(ch.Verify(h, r_p, ID, m, pp), "Verify failed");
            }
        }
    }
}
