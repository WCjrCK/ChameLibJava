package scheme.IBCH.IB_CH_MD_LSX_2022;

import it.unisa.dia.gas.jpbc.Element;
import scheme.IBCH.PbcScheme;

public class PBC extends PbcScheme{
    public PBC(curve.PBC curve) {
        super(curve);
    }

    public static class PublicParam{
        public Element g, g1, g2, egg, eg2g;
    }
    public static class MasterSecrtKey{
        public Element a, b;
    }
    public static class Trapdoor{
        public Element td1, td2;
    }
    public static class HashValue{
        public Element h1;
    }
    public static class Randomness{
        public Element r1, r2;
    }
   
    public void SetUp(PublicParam pp, MasterSecrtKey msk) {
        pp.g = GetG1Element();

        msk.a = GetZnElement();
        msk.b = GetZnElement();

        pp.g1 = pp.g.powZn(msk.a);
        pp.g2 = pp.g.powZn(msk.b);


        pp.egg = pairing.pairing(pp.g, pp.g).getImmutable();
        pp.eg2g = pairing.pairing(pp.g2, pp.g).getImmutable();
    }

    public void KeyGen(Trapdoor td, Element ID, MasterSecrtKey msk, PublicParam pp) {
        // td1
        td.td1 = GetZnElement();

        // td2
        td.td2 = pp.g.powZn(msk.b.sub(td.td1).div(msk.a.sub(ID)));
    }

    public void Hash(HashValue h, Randomness r, Element ID, Element m, PublicParam pp) {
        // r1
        r.r1 = GetZnElement();
        // r2
        r.r2 = GetG1Element();

        h.h1 = pp.eg2g.powZn(m).mul(pp.egg.powZn(r.r1)).mul(pairing.pairing(r.r2, pp.g1.div(pp.g.powZn(ID))));
    }

    public boolean Check(HashValue h, Randomness r, Element ID, Element m, PublicParam pp){
        return pp.eg2g.powZn(m).mul(pp.egg.powZn(r.r1)).mul(pairing.pairing(r.r2, pp.g1.div(pp.g.powZn(ID)))).isEqual(h.h1);
    }

    public void Adapt(Randomness r_p, HashValue h, Element m, Randomness r, Element m_p, Trapdoor td) {
        r_p.r1 = r.r1.add(m.sub(m_p).mul(td.td1));
        r_p.r2 = r.r2.mul(td.td2.powZn(m.sub(m_p)));
    }

}
