package Encryption.PKE.RSA;

import Encryption.PKE.PKE;

import java.math.BigInteger;
import java.util.Map;
import java.util.Random;

import static utils.Func.phi;

public class Scheme extends PKE<PublicParam, PublicKey, SecretKey, PlainText, CipherText> {
    @Override
    public final PublicParam createPublicParam(Map<String, Object> params) {
        return new PublicParam(params);
    }

    @Override
    public final void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        Random rand = new Random();
        if (pp.e_bit < 0) pk.e = new BigInteger("65537");
        else pk.e = BigInteger.probablePrime(pp.e_bit, rand);
        BigInteger phi;
        do {
            sk.p = BigInteger.probablePrime(pp.p_bit, rand);
            sk.q = BigInteger.probablePrime(pp.q_bit, rand);
            phi = phi(sk.p, sk.q);
        } while (phi.gcd(pk.e).compareTo(BigInteger.ONE) != 0);
        pk.N = sk.p.multiply(sk.q);
        sk.d = pk.e.modInverse(phi);
    }

    @Override
    public void Encrypt(CipherText ct, PublicParam pp, PublicKey pk, PlainText pt) {
        ct.ct = pt.pt.modPow(pk.e, pk.N);
    }

    @Override
    public void Decrypt(PlainText pt, PublicParam pp, PublicKey pk, SecretKey sk, CipherText ct) {
        pt.pt = ct.ct.modPow(sk.d, pk.N);
    }
}
