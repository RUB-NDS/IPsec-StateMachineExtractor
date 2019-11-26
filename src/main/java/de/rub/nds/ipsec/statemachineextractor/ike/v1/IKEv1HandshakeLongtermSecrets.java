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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1HandshakeLongtermSecrets {

    private byte[] preSharedKey = "AAAA".getBytes();
    private PublicKey peerPublicKey;
    private PrivateKey myPrivateKey;

    private final String CSR1PrivPEM
            = "MIIEpQIBAAKCAQEA1VnMrbauriqEy+hGC8HvXJRnoIu7lIOERAg7gQXh/4PN1zvN"
            + "vtSKbndOCCBL2eH6U+NYu8wMy9zButuiVALq45HHdnklPuViQTLZK8VO11xOBKZ2"
            + "f8G0RJUtWfWTArFjaKI0t4DXuEXewyEDyYuuz5WKiTSFTNhEoyGKrkWne31nwJiD"
            + "n7oKm/b/UQ55NYDHa/9gVU6CNl+0KRqeuFRFnWpHX+MqpMSN4DNgfDkiDC1Knas5"
            + "QNwvteZMTV6PP1zBMbX2rCa5QoEypy2S8DKLZqsJ12zNvbjmOOpLXblOU6ZlHsxP"
            + "zF2kfhSQrv2E2/B/Mlv3PyPmbuq/4NKAxHrifQIDAQABAoIBAF55xn5CQDYV0/pr"
            + "n+EC/xjTCtR4LBeG6aIqtxbaYQqB9jvSWrifa7GhGSfWDWCthelx6lA2+o+n8Q3q"
            + "xoZHSHZ/joEzAkBI2WqftrWASPprAI1knWLThx07pfqJGZF+tdOWyJtd7ajHH+7u"
            + "hrvQJBf+U3uQi1rNBg/rAXtMku7GeO9HQT8PKLlT4hrRDAMrXySd0mIpHbFMVZdP"
            + "0Uz5d55KlXcddg9R1s4wZ4wUSjaUI8GK4AJ9KavAsnglO0rEkrCUW4U2qMZIkF42"
            + "4bGah8xuVr/SqjwSD+GDCpx0dZOmA2nnzqL36+pRzV88Dp5SA9QDti8wnvZRQGQp"
            + "j1wlra0CgYEA17jXwblWZ13qlwrlZtvKzJslHwVMUNRJYHf5BM6r/G8f/hXzhkRw"
            + "rdezebaDI0/kCKCQowlbY50AeA/350IyD8qiq7ZTOHIuHMNuB47jBfPoQWT1BFRV"
            + "D2Ukmv3xR40gry9Vw/kto483P/aCR0G4iCGmjd+3t8sN/FaNNoBowDsCgYEA/S+d"
            + "QZxJnfaHl29RnYwKjf0iohBHonngtC5qRg9sR2IoNAzOS+JKjxAsFbJilopoclKl"
            + "cfnisYmRVC8T+KQitu6jnZVY3vjESoBQP4o9L/HbASF30A5ul7cfJMY4p75mzzn7"
            + "jCT9ieFKisgMCrosFygSPD6OeAYwvEJMhxc0tKcCgYEAu/oiaHksRZ6dEUk5ZUwZ"
            + "h/mZe1KOkdCqsBlbMUk2rR3YbvyJ3HI/Df1sM59K3rZ7Ktlfr/IzZLYm9nhTuX0B"
            + "Sql03tRd6E32yLGza3qjcUh9Fp72svMZu/SS1Ux7t7HOzVkeD0tO7bualW4lUBqA"
            + "xn8sN2y/FrUmVsDFBL0YiokCgYEA7cKRAtQprdWdb3ByTGj+YGie5WI0Yzfg9FPC"
            + "KRjCriZXasm70TconUCqpZVnT8eaXgGOrIHliKOPfmbXcl9w2ikwLQPa+UjTzMLC"
            + "mWjQHP4ak+1B/ngPExo8fORIv/3lviTNPMZf8eNHhRxncotybCyNM1XrpHrruV7p"
            + "TtNUA3ECgYEAwLrD4dKcotJFcx1DEqU9FOOQVeujgzW8b+cpX8y/Czq1CImFPbqT"
            + "8CwcNhgDHLCa3gOvHWptQeM4iG6aAty1F0dVXS+QGLBFq9HFPBn5Nj0eWjCV6+QZ"
            + "YuuKKgdda6kh4/eFa7Ko9uCSmCJyNouo6l21a3I4LeKfsSuddZK6sio=";

    private final String CSR2PubPEM
            = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCr7TcTUIPfXO2Ly1vptfTPws92"
            + "2g9FpIfMJLpbu2JL/2++stk/VVmJeqssidZNW1uMP8XeHLUby/LdRk5z8lFehHvn"
            + "uQwYyWMbaMJq9s/yCiFB5DD1TkzyOaGgXiiDUWYIIIbUzpt5CnUgXq8CkVvR8OJ7"
            + "e7iZoEiuSJAGC/mhywIDAQAB";

    public IKEv1HandshakeLongtermSecrets() throws GeneralSecurityException {
        byte[] decoded = Base64.getDecoder().decode(CSR1PrivPEM);
        KeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        myPrivateKey = kf.generatePrivate(spec);
        decoded = Base64.getDecoder().decode(CSR2PubPEM);
        spec = new X509EncodedKeySpec(decoded);
        peerPublicKey = kf.generatePublic(spec);
    }

    public byte[] getPreSharedKey() {
        return preSharedKey;
    }

    public PublicKey getPeerPublicKey() {
        return peerPublicKey;
    }

    public PrivateKey getMyPrivateKey() {
        return myPrivateKey;
    }

    public void setPreSharedKey(byte[] preSharedKey) {
        this.preSharedKey = preSharedKey;
    }

    public void setPeerPublicKey(PublicKey peerPublicKey) {
        this.peerPublicKey = peerPublicKey;
    }

    public void setMyPrivateKey(PrivateKey myPrivateKey) {
        this.myPrivateKey = myPrivateKey;
    }

}
