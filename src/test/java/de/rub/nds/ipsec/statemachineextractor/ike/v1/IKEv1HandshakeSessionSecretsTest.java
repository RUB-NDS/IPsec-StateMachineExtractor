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

    /**
     * Test of computeSecretKeys method, of class IKEv1HandshakeSessionSecrets.
     */
    @Test
    public void testComputeSecretKeys() throws Exception {
        IKEv1Handshake handshake = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        handshake.adjustCiphersuite(SecurityAssociationPayloadFactory.PSK_AES128_SHA1_G2);
        IKEv1HandshakeSessionSecrets instance = handshake.secrets;
        instance.generateDefaults();
        handshake.ltsecrets.setPreSharedKey("AAAA".getBytes());
        instance.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("7116900aa5c2880d"));
        instance.setResponderCookie(DatatypeHelper.hexDumpToByteArray("047ad6f8b3d0abb7"));
        instance.setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("4654fdd74594982a"));
        instance.setResponderNonce(DatatypeHelper.hexDumpToByteArray("3673e64987b4956dbb8b933399251a5abf88f557a723b802b345f838667e9a4e"));
        instance.setKeyExchangeData(DatatypeHelper.hexDumpToByteArray("75fb75db0749d4b15d9bb067b63399f790246dd7919d0c0a88fc34dd76eb9ad204e162b261914c0966a2d32d05178d4c0f0ec3817692fca675678f2fd2a6869188b943e33ad44cc859a5af98d6d5332c538cff4174ee737c8624de910cc40bd953f7940d1b2d8a681cee03c85199fbe773bfa100ffea5fcb82eed25a399b0b3e"));
        instance.setPeerKeyExchangeData(DatatypeHelper.hexDumpToByteArray("2096a31ff922e5224d9d19f06a41e2d9aebe1180d4e5cbc3d6ea166e2b8810d5ddd048375025ae9bf895ad40c508cd8b9398bded0d00ae7e77c1a1eb31930495106892630152a926a45037606cda4651340082fc10558786b4d8c4e6d72222d580d9a30d9c3b7fe9c348a6eadc5e79a24fe4b4364297b5ff71914ef8a6980e73"));
        instance.setSAOfferBody(DatatypeHelper.hexDumpToByteArray("00000001000000010000002c01010001000000240101000080010007800e0080800200028004000280030001800b0001800c7080"));
        instance.setPeerIdentificationPayloadBody(DatatypeHelper.hexDumpToByteArray("010000000a00030a"));
        instance.setDHSecret(DatatypeHelper.hexDumpToByteArray("19B67B23EB5F792EC9D7E11D16501CA20F2A2D0B230D525CD824DFB16867B515DC2CE9560B20B2149BFB360C1662C26A5AD7FE1FAA86E66213238C80B2ED46CCB821BF5043093027EB6E32C71685A093306DF20C24190C7F93947FA21E56D10E4C5B7063B2B4DC1747F1DF0BD46975D1825EEDE335E3ACBAD71A063CECF866C7"));

        instance.computeSecretKeys();

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("49856BC53F30DB8CE55F5BEFAE9E42431279550C"), instance.getSKEYID());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("E5D7368180A8766F09C90CC9AC15182D3CD492EE"), instance.getSKEYID_d());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("92DE109FE83047C95812B600820F1476CD24AA49"), instance.getSKEYID_a());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("DE5D24679AD21491E63E2D7173017769CD7B9BC5"), instance.getSKEYID_e());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("DE5D24679AD21491E63E2D7173017769"), instance.getKa());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("139568606DF1337CBCBC8FA7D201C8A8"), instance.getIV());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("BA8C49CFD796BDC78E63FF6B5A858FC289DAD933"), instance.getHASH_R());
    }

}
