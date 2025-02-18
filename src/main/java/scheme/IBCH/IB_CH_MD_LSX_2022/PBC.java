package scheme.IBCH.IB_CH_MD_LSX_2022;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import scheme.IBCH.PbcElements;
import scheme.IBCH.PbcScheme;

public class PBC extends PbcScheme{
    public PBC(curve.PBC curve, Group group_G1, Group group_G2) {
        super(curve, group_G1, group_G2);
    }

    public static class IB_CH_MD_LSX_2022_pp extends PbcElements {}
    public static class IB_CH_MD_LSX_2022_msk extends PbcElements {}
    public static class IB_CH_MD_LSX_2022_td extends PbcElements {}
    public static class IB_CH_MD_LSX_2022_h extends PbcElements {}
    public static class IB_CH_MD_LSX_2022_r extends PbcElements {}

    public enum PP{
        g, g1, g2, egg, eg2g;
    }

    public enum MSK{
        a, b
    };

    public enum TD{
        td1, td2
    };

    public enum HASHVALUE{
        h1
    };

    public enum RANDOMNESS{
        r1, r2
    };

   
    public void SetUp(IB_CH_MD_LSX_2022_pp pp, IB_CH_MD_LSX_2022_msk msk, IB_CH_MD_LSX_2022_td td, IB_CH_MD_LSX_2022_h h, IB_CH_MD_LSX_2022_r r, IB_CH_MD_LSX_2022_r r_p) {
        pp.init(5);
        msk.init(2);
        td.init(2);
        h.init(1);
        r.init(2);
        r_p.init(2);

        element_random(tmp_G);
        pp.set(PP.g, tmp_G);

        element_random(tmp_Zn);
        msk.set(MSK.a, tmp_Zn);
        element_random(tmp_Zn_2);
        msk.set(MSK.b, tmp_Zn_2);

        element_pow_zn(tmp_G_2, tmp_G, tmp_Zn);
        pp.set(PP.g1, tmp_G_2);
        element_pow_zn(tmp_G_2, tmp_G, tmp_Zn_2);
        pp.set(PP.g2, tmp_G_2);

        element_pairing(tmp_GT, tmp_G, tmp_G);
        pp.set(PP.egg, tmp_GT);
        element_pairing(tmp_GT, tmp_G_2, tmp_G);
        pp.set(PP.eg2g, tmp_GT);
    }

    public void KeyGen(IB_CH_MD_LSX_2022_td td, Element ID, IB_CH_MD_LSX_2022_msk msk, IB_CH_MD_LSX_2022_pp pp) {
        // t
        element_random(tmp_Zn);
        
        // td1
        td.set(TD.td1, tmp_Zn);

        // td2
        element_sub(this.tmp_Zn, msk.get(MSK.b), tmp_Zn);
        element_sub(this.tmp_Zn_2, msk.get(MSK.a), ID);
        element_div(this.tmp_Zn_3, this.tmp_Zn, this.tmp_Zn_2);
        element_pow_zn(tmp_G, pp.get(PP.g), this.tmp_Zn_3);
        td.set(TD.td2, tmp_G);
    }

    public void Hash(IB_CH_MD_LSX_2022_h h, IB_CH_MD_LSX_2022_r r, Element ID, Element m, IB_CH_MD_LSX_2022_pp pp) {
        // r1
        element_random(tmp_Zn);
        r.set(RANDOMNESS.r1, tmp_Zn);
        // r2
        element_random(tmp_G);
        r.set(RANDOMNESS.r2, tmp_G);

        element_pow_zn(this.tmp_GT, pp.get(PP.eg2g), m);
        element_pow_zn(this.tmp_GT_2, pp.get(PP.egg), tmp_Zn);
        //g1 / g^ID
        element_pow_zn(this.tmp_G_2, pp.get(PP.g), ID);
        element_div(this.tmp_G_3, pp.get(PP.g1), this.tmp_G_2);
        element_pairing(this.tmp_GT_3, tmp_G, this.tmp_G_3);

        element_mul(tmp_GT, this.tmp_GT, this.tmp_GT_2);
        element_mul(tmp_GT, tmp_GT, this.tmp_GT_3);
        h.set(HASHVALUE.h1, tmp_GT);
    }

    public boolean Check(IB_CH_MD_LSX_2022_h h, IB_CH_MD_LSX_2022_r r, Element ID, Element m, IB_CH_MD_LSX_2022_pp pp){
        element_set(tmp_Zn, r.get(RANDOMNESS.r1));
        element_set(tmp_G, r.get(RANDOMNESS.r2));

        element_pow_zn(this.tmp_GT, pp.get(PP.eg2g), m);
        element_pow_zn(this.tmp_GT_2, pp.get(PP.egg), tmp_Zn);
        //g1 / g^ID
        element_pow_zn(this.tmp_G_2, pp.get(PP.g), ID);
        element_div(this.tmp_G_3, pp.get(PP.g1), this.tmp_G_2);
        element_pairing(this.tmp_GT_3, tmp_G, this.tmp_G_3);

        element_mul(tmp_GT, this.tmp_GT, this.tmp_GT_2);
        element_mul(tmp_GT, tmp_GT, this.tmp_GT_3);
        
        return element_cmp(h.get(HASHVALUE.h1), tmp_GT) == 0;
    }

    public void Adapt(IB_CH_MD_LSX_2022_r r_p, IB_CH_MD_LSX_2022_h h, Element m, IB_CH_MD_LSX_2022_r r, Element m_p, IB_CH_MD_LSX_2022_td td) {
        element_sub(this.tmp_Zn, m, m_p);
        element_mul(this.tmp_Zn_2, this.tmp_Zn, td.get(TD.td1));
        element_add(tmp_Zn_2, r.get(RANDOMNESS.r1), this.tmp_Zn_2);
        r_p.set(RANDOMNESS.r1, tmp_Zn_2);

        element_pow_zn(this.tmp_G, td.get(TD.td2), this.tmp_Zn);
        element_mul(tmp_G, r.get(RANDOMNESS.r2), this.tmp_G);
        r_p.set(RANDOMNESS.r2, tmp_G);
    }

    public boolean Verify(IB_CH_MD_LSX_2022_h h, IB_CH_MD_LSX_2022_r r_p, Element ID, Element m_p, IB_CH_MD_LSX_2022_pp pp) {
        return Check(h, r_p, ID, m_p, pp);
    }
}
