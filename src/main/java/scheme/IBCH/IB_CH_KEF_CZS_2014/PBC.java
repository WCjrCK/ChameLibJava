package scheme.IBCH.IB_CH_KEF_CZS_2014;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import scheme.IBCH.PbcElements;
import scheme.IBCH.PbcScheme;
import utils.Hash;

public class PBC extends PbcScheme{
    public PBC(curve.PBC curve, Group group_G1, Group group_G2) {
        super(curve, group_G1, group_G2);
    }

    public static class IB_CH_KEF_CZS_2014_pp extends PbcElements {};
    public static class IB_CH_KEF_CZS_2014_msk extends PbcElements {};
    public static class IB_CH_KEF_CZS_2014_td extends PbcElements {};
    public static class IB_CH_KEF_CZS_2014_h extends PbcElements {};
    public static class IB_CH_KEF_CZS_2014_r extends PbcElements {};

    public enum PP{
        P, Ppub
    };

    public enum TD{
        SID
    };

    public enum RANDOMNESS{
        r1, r2
    };

    public enum HASHVALUE{
        h1
    };

    public void SetUp(IB_CH_KEF_CZS_2014_pp pp, IB_CH_KEF_CZS_2014_msk msk, IB_CH_KEF_CZS_2014_td td, IB_CH_KEF_CZS_2014_h h, IB_CH_KEF_CZS_2014_r r, IB_CH_KEF_CZS_2014_r r_p) {
        pp.init(2);
        td.init(1);
        h.init(1);
        r.init(2);
        r_p.init(2);
        msk.init(1);
        
        // P
        element_random(tmp_G);
        pp.set(PP.P, tmp_G);
        
        // x
        element_random(tmp_Zn);
        msk.set(0, tmp_Zn);
        // Ppub = x * P
        element_mul_zn(tmp_G, tmp_G, tmp_Zn);
        pp.set(PP.Ppub, tmp_G);
    }
    
    /**
     * input : x, ID
     * output: SID
     */
    public void Extract(IB_CH_KEF_CZS_2014_td td, String ID, IB_CH_KEF_CZS_2014_msk msk) {  
        // QID = H(ID)
        H(tmp_H, ID);
        // SID = x * QID
        element_mul_zn(tmp_H, tmp_H, msk.get(0));
        td.set(TD.SID, tmp_H);
    }
     
    
    /**
     * input : (y,h,m),(u11,u12,u2)
     * output: res
     */
    private void H(Element res, String m) {
        Hash.H_string_1_PBC_1(res, m);
    }
    
    /**
     * input : ID, L, m
     * output: r(r1,r2), h
     */
    public void Hash(IB_CH_KEF_CZS_2014_h h, IB_CH_KEF_CZS_2014_r r, String ID, String L, Element m, IB_CH_KEF_CZS_2014_pp pp) {
        // a
        element_random(tmp_Zn);
        // QID = H(ID)
        H(tmp_H, ID);
    
        // r1 = a * P
        element_mul_zn(tmp_G, pp.get(PP.P), tmp_Zn);
        r.set(RANDOMNESS.r1, tmp_G);
        // r2 = e(a * Ppub, QID)
        element_mul_zn(tmp_G, pp.get(PP.Ppub), tmp_Zn);
        element_pairing(tmp_GT, tmp_G, tmp_H);
        r.set(RANDOMNESS.r2, tmp_GT);
    
        // h = a * P + m * H(L)
        H(tmp_G, L);
        element_mul_zn(tmp_G, tmp_G, m);
        element_add(tmp_G, r.get(RANDOMNESS.r1), tmp_G);
        h.set(HASHVALUE.h1, tmp_G);
    }
    
    /**
     * input : h, L, m, r1
     * output: bool
     */
    public boolean Check(IB_CH_KEF_CZS_2014_h h, IB_CH_KEF_CZS_2014_r r, String L, Element m, IB_CH_KEF_CZS_2014_td td){
        // h = r1 + m * H(L)
        H(tmp_G, L);
        element_mul_zn(tmp_G, tmp_G, m);
        element_add(tmp_G, r.get(RANDOMNESS.r1), tmp_G);
        if(element_cmp(h.get(HASHVALUE.h1), tmp_G) != 0){
            return false;
        }
    
        // check the correctness of the r
        // e(a * P,SID) == e(a * Ppub, QID)
        // e(r1, SID) == r2
        element_pairing(this.tmp_GT, r.get(RANDOMNESS.r1), td.get(TD.SID));
        if(element_cmp(this.tmp_GT, r.get(RANDOMNESS.r2)) != 0){
            return false;
        }
        return true;
    }
    
    /**
     * input : SID, ID, L, h, m, r1, r2, m_p
     * output: r_p(r1_p, r2_p)
     */
    public void Adapt(IB_CH_KEF_CZS_2014_r r_p, Element m_p, IB_CH_KEF_CZS_2014_h h, IB_CH_KEF_CZS_2014_r r, String L, Element m, IB_CH_KEF_CZS_2014_td td) {
        // r1_p = r1 + (m - m_p) * H(L)
        element_sub(this.tmp_Zn, m, m_p);
        this.H(this.tmp_G, L);
        element_mul_zn(this.tmp_G_2, this.tmp_G, this.tmp_Zn);
        element_add(tmp_G_2, r.get(RANDOMNESS.r1), this.tmp_G_2);
        r_p.set(RANDOMNESS.r1, tmp_G_2);
        
        // r2_p = r2 * e(SID, H(L))^(m-m_p)
        element_pairing(this.tmp_GT, tmp_G, td.get(TD.SID));
        element_pow_zn(this.tmp_GT_2, this.tmp_GT, this.tmp_Zn);
        element_mul(tmp_GT_2, r.get(RANDOMNESS.r2), this.tmp_GT_2);
        r_p.set(RANDOMNESS.r2, tmp_GT_2);
    
        // check the correctness of the r_p
        // e(r1_p, SID) == r2_p
        element_pairing(this.tmp_GT_3, r_p.get(RANDOMNESS.r1), td.get(TD.SID));
        if(element_cmp(this.tmp_GT_3, r_p.get(RANDOMNESS.r2)) != 0){
            throw new RuntimeException("Adapt(): Adapt failed, r_p is invalid");
        }
    }
    
    /**
     * input : h, L, m_p, r1_p
     * output: bool
     */
    public boolean Verify(IB_CH_KEF_CZS_2014_h h, IB_CH_KEF_CZS_2014_r r, String L, Element m, IB_CH_KEF_CZS_2014_td td) {
        return this.Check(h, r, L, m, td);
    }
}