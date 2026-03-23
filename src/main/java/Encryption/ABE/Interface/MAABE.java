package Encryption.ABE.Interface;

import Encryption.ABE.ABEConfig;
import Encryption.ABE.MAABE.Components.*;

public interface MAABE<
        PP extends PublicParam,
        PK extends PublicKey,
        PKG extends PublicKeyGroup,
        SK extends SecretKey,
        SKG extends SecretKeyGroup,
        Auth extends Authority,
        U extends User,
        ID extends Identity,
        A extends Attribute,
        P extends Policy,
        PT extends PlainText<PT>,
        CT extends CipherText<CT, P>
        > {
    void Setup(PP pp);

    void AuthSetup(Auth auth, PP pp);

    void UserSetup(U user, PP pp);

    void KeyGen(PK pk, SK sk, PP pp, Auth auth, ID id, A attr);

    void Encrypt(CT ct, PP pp, PKG pkg, P P, PT pt);

    void Decrypt(PT pt, PP pp, ID id, SKG skg, CT ct);

    PP createPublicParam(ABEConfig abeConfig);
}
