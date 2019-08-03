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
            = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJv/Vp6TvqPOmVYP7n5JJo+SO3"
            + "KPFjxsoNMrlRWjOppAoHJu7lkQM6Q6dWxTnijO7q6CJ90kBcp1DQtndmP5G590NN"
            + "c3w9PtQlM8WIYDnwEQ8ssA4Zd0VNLtCr1ePH5O97hV3hHggcc17BFr1nIubRVHiq"
            + "tdDwhJce19+OlZiAEwIDAQAB";

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
