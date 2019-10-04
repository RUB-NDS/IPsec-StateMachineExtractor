/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.net.InetAddress;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1HandshakeSessionSecretsTest {

    static {
        CryptoHelper.prepare();
    }

    private static final String TESTDHSECRET = 
              "19B67B23EB5F792EC9D7E11D16501CA2"
            + "0F2A2D0B230D525CD824DFB16867B515"
            + "DC2CE9560B20B2149BFB360C1662C26A"
            + "5AD7FE1FAA86E66213238C80B2ED46CC"
            + "B821BF5043093027EB6E32C71685A093"
            + "306DF20C24190C7F93947FA21E56D10E"
            + "4C5B7063B2B4DC1747F1DF0BD46975D1"
            + "825EEDE335E3ACBAD71A063CECF866C7";

    /**
     * Test of computeSecretKeys method, of class IKEv1HandshakeSessionSecrets.
     */
    @Test
    public void testComputeSecretKeys() throws Exception {
        IKEv1Handshake handshake = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        handshake.adjustCiphersuite(SecurityAssociationPayloadFactory.PSK_AES128_SHA1_G2);
        IKEv1HandshakeSessionSecrets instance = handshake.secrets;
        instance.generateDefaults();
        instance.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("7116900aa5c2880d"));
        instance.setResponderCookie(DatatypeHelper.hexDumpToByteArray("047ad6f8b3d0abb7"));
        instance.setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("4654fdd74594982a"));
        instance.setResponderNonce(DatatypeHelper.hexDumpToByteArray("3673e64987b4956dbb8b933399251a5abf88f557a723b802b345f838667e9a4e"));
        instance.setDHSecret(DatatypeHelper.hexDumpToByteArray(TESTDHSECRET));
        instance.computeSecretKeys();
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("49856BC53F30DB8CE55F5BEFAE9E42431279550C"), instance.getSKEYID().getEncoded());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("E5D7368180A8766F09C90CC9AC15182D3CD492EE"), instance.getSKEYID_d().getEncoded());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("92DE109FE83047C95812B600820F1476CD24AA49"), instance.getSKEYID_a().getEncoded());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("DE5D24679AD21491E63E2D7173017769CD7B9BC5"), instance.getSKEYID_e().getEncoded());
    }

}
