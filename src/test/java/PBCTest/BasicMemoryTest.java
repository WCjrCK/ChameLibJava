package PBCTest;

import curve.PBC;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
//import org.apache.lucene.util.RamUsageEstimator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
//import org.openjdk.jol.info.ClassLayout;

import static utils.Func.InitialLib;
import static utils.Func.PairingGen;

@Disabled
@SuppressWarnings({"rawtypes", "ImplicitArrayToString"})
public class BasicMemoryTest extends BasicParam {
    @BeforeAll
    static void initTest() {
        InitialLib();
        repeat_cnt = 10;
    }

    @DisplayName("test PBC memory cost")
    @ParameterizedTest(name = "test curve {0}")
    @EnumSource(PBC.class)
    void JPBCTest(PBC curve) {
        var pairing = PairingGen(curve);
        Field[] GList = {pairing.getG1(), pairing.getG2(), pairing.getGT(), pairing.getZr()};
        Element[][] Elements = new Element[4][repeat_cnt];
        for (int i = 0; i < repeat_cnt; i++) for (int j = 0; j < 4; j++) Elements[j][i] = GList[j].newRandomElement().getImmutable();
//        System.out.println(RamUsageEstimator.shallowSizeOf(Elements[0][0]));
//        System.out.println(ClassLayout.parseInstance(Elements[0][0]).toPrintable());
        System.out.println(Elements[0][0].toBytes());
    }
}
