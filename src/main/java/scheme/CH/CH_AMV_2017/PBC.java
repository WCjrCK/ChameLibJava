package scheme.CH.CH_AMV_2017;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;

import java.util.HashMap;

/*
 * Redactable Blockchain or Rewriting History in Bitcoin and Friends
 * P25. 4.4.2 Random Oracle Model Instantiation
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        Field Zr, G;
        Element g;
        public AE.PKE_CPA_AMV_2017.PBC.PublicParam PKE_CPA_PP = new AE.PKE_CPA_AMV_2017.PBC.PublicParam();
        public AE.PKE_CCA_AMV_2017.PBC.PublicParam PKE_CCA_PP = new AE.PKE_CCA_AMV_2017.PBC.PublicParam();
        public HashMap<String, Element> Omega = new HashMap<>();
        public HashMap<String, Element> Omega_inv = new HashMap<>();

        public Element GetGElement() {
            return G.newRandomElement().getImmutable();
        }

        public Element GetZrElement() {
            return Zr.newRandomElement().getImmutable();
        }
    }

    public static class PublicKey {
        public AE.PKE_CPA_AMV_2017.PBC.PublicKey PKE_CPA_PK = new AE.PKE_CPA_AMV_2017.PBC.PublicKey();
        public AE.PKE_CCA_AMV_2017.PBC.PublicKey PKE_CCA_PK = new AE.PKE_CCA_AMV_2017.PBC.PublicKey();
        public Element y;
    }

    public static class SecretKey {
        public AE.PKE_CPA_AMV_2017.PBC.SecretKey PKE_CPA_SK = new AE.PKE_CPA_AMV_2017.PBC.SecretKey();
        public AE.PKE_CCA_AMV_2017.PBC.SecretKey PKE_CCA_SK = new AE.PKE_CCA_AMV_2017.PBC.SecretKey();
        public Element x;
    }

    public static class HashValue {
        public Element h;
    }

    public static class Randomness {
        public Element r;
    }

    public static class EncRandomness {
        public base.NIZK.PBC.DL_Proof pi_1, pi_2;
        public base.NIZK.PBC.EQUAL_DL_Proof pi_3;
        public base.NIZK.PBC.REPRESENT_Proof pi_4, pi_5;
        AE.PKE_CPA_AMV_2017.PBC.CipherText PKE_CPA_CT = new AE.PKE_CPA_AMV_2017.PBC.CipherText();
        AE.PKE_CCA_AMV_2017.PBC.CipherText PKE_CCA_CT = new AE.PKE_CCA_AMV_2017.PBC.CipherText();
    }

    AE.PKE_CPA_AMV_2017.PBC PKE_CPA = new AE.PKE_CPA_AMV_2017.PBC();
    AE.PKE_CCA_AMV_2017.PBC PKE_CCA = new AE.PKE_CCA_AMV_2017.PBC();

    private void genR(HashValue H, EncRandomness ER, Randomness R, PublicParam pp, PublicKey pk, Element m) {
        ER.pi_1 = new base.NIZK.PBC.DL_Proof(pp.Zr, R.r, pp.g, H.h.mul(pk.y.powZn(m)));

        Element rho_1 = pp.GetZrElement();
        AE.PKE_CPA_AMV_2017.PBC.PlainText PKE_CPA_PT = new AE.PKE_CPA_AMV_2017.PBC.PlainText();
        PKE_CPA_PT.m = R.r;
        PKE_CPA.Encrypt(ER.PKE_CPA_CT, pp.PKE_CPA_PP, pk.PKE_CPA_PK, PKE_CPA_PT, rho_1);
        ER.pi_2 = new base.NIZK.PBC.DL_Proof(pp.Zr, rho_1, pp.PKE_CPA_PP.g, ER.PKE_CPA_CT.c_1);

        Element rho_2 = pp.GetZrElement();
        AE.PKE_CCA_AMV_2017.PBC.PlainText PKE_CCA_PT = new AE.PKE_CCA_AMV_2017.PBC.PlainText();
        PKE_CCA_PT.m = R.r;
        PKE_CCA.Encrypt(ER.PKE_CCA_CT, pp.PKE_CCA_PP, pk.PKE_CCA_PK, PKE_CCA_PT, rho_2);
        ER.pi_3 = new base.NIZK.PBC.EQUAL_DL_Proof(pp.Zr, rho_2, pp.PKE_CCA_PP.g_1, ER.PKE_CCA_CT.c_1, pp.PKE_CCA_PP.g_2, ER.PKE_CCA_CT.c_2);

        ER.pi_4 = new base.NIZK.PBC.REPRESENT_Proof(pp.Zr, ER.PKE_CCA_CT.c_4, pk.PKE_CCA_PK.y_1, rho_2, pk.PKE_CCA_PK.y_2, rho_2.mul(pp.PKE_CCA_PP.H(ER.PKE_CCA_CT.c_1, ER.PKE_CCA_CT.c_2, ER.PKE_CCA_CT.c_3)));
        ER.pi_5 = new base.NIZK.PBC.REPRESENT_Proof(pp.Zr, ER.PKE_CPA_CT.c_2.div(ER.PKE_CCA_CT.c_3), pk.PKE_CPA_PK.y, rho_1, pk.PKE_CCA_PK.y_3.invert(), rho_2);
    }

    public void SetUp(PublicParam pp, curve.PBC curve, Group group) {
        Pairing pairing = Func.PairingGen(curve);
        pp.G = Func.GetPBCField(pairing, group);
        pp.Zr = pairing.getZr();
        pp.g = pp.GetGElement();
        PKE_CPA.SetUp(pp.PKE_CPA_PP, curve, group);
        PKE_CCA.SetUp(pp.PKE_CCA_PP, curve, group);
        pp.PKE_CPA_PP.Omega = pp.Omega;
        pp.PKE_CCA_PP.Omega = pp.Omega;
        pp.PKE_CPA_PP.Omega_inv = pp.Omega_inv;
        pp.PKE_CCA_PP.Omega_inv = pp.Omega_inv;
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        PKE_CPA.KeyGen(pk.PKE_CPA_PK, sk.PKE_CPA_SK, pp.PKE_CPA_PP);
        PKE_CCA.KeyGen(pk.PKE_CCA_PK, sk.PKE_CCA_SK, pp.PKE_CCA_PP);
        sk.x = pp.GetZrElement();
        pk.y = pp.g.powZn(sk.x).getImmutable();
    }

    public void Hash(HashValue H, EncRandomness ER, Randomness R, PublicParam pp, PublicKey pk, Element m) {
        R.r = pp.GetZrElement();

        H.h = pp.g.powZn(R.r).div(pk.y.powZn(m)).getImmutable();
        genR(H, ER, R, pp, pk, m);
    }

    public boolean Check(HashValue H, EncRandomness ER, PublicParam pp, PublicKey pk, Element m) {
        return ER.pi_1.Check(pp.g, H.h.mul(pk.y.powZn(m))) &&
                ER.pi_2.Check(pp.PKE_CPA_PP.g, ER.PKE_CPA_CT.c_1) &&
                ER.pi_3.Check(pp.PKE_CCA_PP.g_1, ER.PKE_CCA_CT.c_1, pp.PKE_CCA_PP.g_2, ER.PKE_CCA_CT.c_2) &&
                ER.pi_4.Check(ER.PKE_CCA_CT.c_4, pk.PKE_CCA_PK.y_1, pk.PKE_CCA_PK.y_2) &&
                ER.pi_5.Check(ER.PKE_CPA_CT.c_2.div(ER.PKE_CCA_CT.c_3), pk.PKE_CPA_PK.y, pk.PKE_CCA_PK.y_3.invert());
    }

    public void Adapt(EncRandomness ER_p, Randomness R_p, HashValue H, EncRandomness ER, PublicParam pp, PublicKey pk, SecretKey sk, Element m, Element m_p) {
        if(!Check(H, ER, pp, pk, m)) throw new RuntimeException("wrong hash value");
        AE.PKE_CPA_AMV_2017.PBC.PlainText CPA_PT = new AE.PKE_CPA_AMV_2017.PBC.PlainText();
        PKE_CPA.Decrypt(CPA_PT, pp.PKE_CPA_PP, sk.PKE_CPA_SK, ER.PKE_CPA_CT);
        Element r = CPA_PT.m;
        R_p.r = r.sub(sk.x.mul(m.sub(m_p))).getImmutable();
        genR(H, ER_p, R_p, pp, pk, m_p);
    }
}
