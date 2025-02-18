package scheme.IBCH.IB_CH_KEF_CZS_2014;

import it.unisa.dia.gas.jpbc.Element;
import scheme.IBCH.PbcScheme;
import utils.Hash;

public class PBC extends PbcScheme{
    public PBC(curve.PBC curve) {
        super(curve);
    }

    public static class PublicParam{
        public Element P, Ppub;
    }
    public static class MasterSecrtKey{
        public Element x;
    }
    public static class Trapdoor{
        public Element SID;
    }
    public static class HashValue{
        public Element h1;
    }
    public static class Randomness{
        public Element r1, r2;
    }


    public void SetUp(PublicParam pp, MasterSecrtKey msk) {
        // P
        pp.P = GetG1Element();
        
        // x
        msk.x = GetZnElement();
        // Ppub = x * P
        pp.Ppub = pp.P.mulZn(msk.x);
    }
    
    public void Extract(Trapdoor td, String ID, MasterSecrtKey msk) {  
        // QID = H(ID)
        // SID = x * QID
        td.SID = H(ID).mulZn(msk.x);
    }
     
    
    private Element H(String m) {
        return Hash.H_string_1_PBC_1(G2, m);
    }
    private Element H2(String m) {
        return Hash.H_string_1_PBC_1(G1, m);
    }
    

    public void Hash(HashValue h, Randomness r, String ID, String L, Element m, PublicParam pp) {
        // a
        Element a = GetZnElement();
 
    
        // r1 = a * P
        r.r1 = pp.P.mulZn(a);

        // r2 = e(a * Ppub, QID)
        r.r2 = pairing.pairing(pp.Ppub.mulZn(a), H(ID)).getImmutable();
    
        // h = a * P + m * H(L)
        h.h1 = r.r1.add(H2(L).mulZn(m));
    }

    public boolean Check(HashValue h, Randomness r, String L, Element m, Trapdoor td){
        // h = r1 + m * H(L)
        if(!r.r1.add(H2(L).mulZn(m)).equals(h.h1)){
            return false;
        }
    
        // check the correctness of the r
        // e(a * P,SID) == e(a * Ppub, QID)
        // e(r1, SID) == r2
        if(!pairing.pairing(r.r1, td.SID).equals(r.r2)){
            return false;
        }
        return true;
    }
    

    public void Adapt(Randomness r_p, Element m_p, HashValue h, Randomness r, String L, Element m, Trapdoor td) {
        // r1_p = r1 + (m - m_p) * H(L)
        r_p.r1 = r.r1.add(H2(L).mulZn(m.sub(m_p)));
        
        // r2_p = r2 * e(SID, H(L))^(m-m_p)
        r_p.r2 = r.r2.mul(pairing.pairing(td.SID, H2(L)).powZn(m.sub(m_p)));
    
        // check the correctness of the r_p
        // e(r1_p, SID) == r2_p
        if(!pairing.pairing(r_p.r1, td.SID).equals(r_p.r2)){
            throw new RuntimeException("Adapt(): Adapt failed, r_p is invalid");
        }
    }
}