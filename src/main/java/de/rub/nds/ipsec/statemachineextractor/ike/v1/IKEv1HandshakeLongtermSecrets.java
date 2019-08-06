/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
class IKEv1HandshakeLongtermSecrets {

    private byte[] preSharedKey = new byte[]{0x00};
    private PublicKey peerPublicKey;

    private String CSR2PEM
            = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxWJ9sySuB3FKqYRwTIPC"
            + "08zDntEo0ywCnRWNSY9bknJ2zBU4F1YliiH5//Li9DdR/j/Ls+ipH5M/ZOFrVuZW"
            + "bbkaqcF5aWmy8LcA/IykimzcgfR3wy+gjtxjP4Igjm/NvHVV3/x3x4Zu4bi34X+G"
            + "z+D3dUNLmNvPe2CGshLjc9BwqohjVozbBe5gNqTzZOGxNIH1EOvTRAqYFtaYwffY"
            + "QLU/JAvE3XRCYhk45zoIeJfHs8w9URDIXkcXyMdBMRfGzZFsyNrjvnwQMyvOwbLb"
            + "N4PWepQqGLMbKJ06NsDcQ8QYMFINw2lGekfxukoWWwOBIe8VOOb3HVCXrSuCe0+d"
            + "bwIDAQAB";

    public IKEv1HandshakeLongtermSecrets() throws GeneralSecurityException {
        byte[] decoded = Base64.getDecoder().decode(CSR2PEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        peerPublicKey = kf.generatePublic(spec);
    }

    public byte[] getPreSharedKey() {
        return preSharedKey;
    }

//    public void setPreSharedKey(byte[] preSharedKey) {
//        this.preSharedKey = preSharedKey;
//    }
    public PublicKey getPeerPublicKey() {
        return peerPublicKey;
    }

}
