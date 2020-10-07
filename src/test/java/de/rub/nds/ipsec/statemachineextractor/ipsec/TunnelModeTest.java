/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec;

import de.rub.nds.ipsec.statemachineextractor.ike.DHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.SecurityAssociationSecrets;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.AuthenticationAlgorithmAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.KeyLengthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class TunnelModeTest {
    
    static {
        CryptoHelper.prepare();
    }

    /**
     * Test of rekey method, of class TunnelMode.
     */
    @Test
    public void testRekeyIKEv1NoAuth() throws Exception {
        ByteArrayInputStream baisIn = new ByteArrayInputStream(DatatypeHelper.hexDumpToByteArray(
                "8665C2AC3CF27716AC796CDB492AE6F444F16D7B83BF01E9578B2C430C8F3AA68BFE47757FB09D"));
        ByteArrayInputStream baisOut = new ByteArrayInputStream(DatatypeHelper.hexDumpToByteArray(
                "7C0C9C9499578C15D01273A34629A585898FB771FB943BC2AB3A999CFFB6680F04FDC89B222560"));
        SecurityAssociationSecrets sas = new SecurityAssociationSecrets(DHGroupEnum.GROUP1_768);
        sas.setInboundKeyMaterial(baisIn);
        sas.setOutboundKeyMaterial(baisOut);
        ESPTransformIDEnum cipher = ESPTransformIDEnum.AES;
        KeyLengthAttributeEnum keylength = KeyLengthAttributeEnum.L128;
        AuthenticationAlgorithmAttributeEnum authAlgo = AuthenticationAlgorithmAttributeEnum.HMAC_SHA;
        TunnelMode instance = new TunnelMode(InetAddress.getLocalHost(), InetAddress.getLocalHost(), sas, cipher, keylength, authAlgo, 0);
        
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("7C0C9C9499578C15D01273A34629A585"), instance.outboundKeyEnc.getEncoded());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("8665C2AC3CF27716AC796CDB492AE6F4"), instance.inboundKeyEnc.getEncoded());
    }
    
    /**
     * Test of rekey method, of class TunnelMode.
     */
    @Test
    public void testRekeyIKEv1WithAuth() throws Exception {
        ByteArrayInputStream baisIn = new ByteArrayInputStream(DatatypeHelper.hexDumpToByteArray(
                "8665C2AC3CF27716AC796CDB492AE6F444F16D7B83BF01E9578B2C430C8F3AA68BFE47757FB09D"));
        ByteArrayInputStream baisOut = new ByteArrayInputStream(DatatypeHelper.hexDumpToByteArray(
                "7C0C9C9499578C15D01273A34629A585898FB771FB943BC2AB3A999CFFB6680F04FDC89B222560"));
        SecurityAssociationSecrets sas = new SecurityAssociationSecrets(DHGroupEnum.GROUP1_768);
        sas.setInboundKeyMaterial(baisIn);
        sas.setOutboundKeyMaterial(baisOut);
        ESPTransformIDEnum cipher = ESPTransformIDEnum.AES;
        KeyLengthAttributeEnum keylength = KeyLengthAttributeEnum.L128;
        AuthenticationAlgorithmAttributeEnum authAlgo = AuthenticationAlgorithmAttributeEnum.HMAC_SHA;
        TunnelMode instance = new TunnelMode(InetAddress.getLocalHost(), InetAddress.getLocalHost(), sas, cipher, keylength, authAlgo, 0);
        
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("7C0C9C9499578C15D01273A34629A585"), instance.outboundKeyEnc.getEncoded());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("8665C2AC3CF27716AC796CDB492AE6F4"), instance.inboundKeyEnc.getEncoded());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("898FB771FB943BC2AB3A999CFFB6680F04FDC89B"), instance.outboundKeyAuth.getEncoded());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("44F16D7B83BF01E9578B2C430C8F3AA68BFE4775"), instance.inboundKeyAuth.getEncoded());
    }
    
    /**
     * Test of rekey method, of class TunnelMode.
     */
    @Test
    public void testRekeyIKEv2NoAuth() throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(DatatypeHelper.hexDumpToByteArray(
                "3FC4F52119015EAF732A8A028E7A8190A078477837E80A4FF1D3379CCEF52888C8613BC2EECBF1A1905CF05284718C63597D516C1B354E66C029B26F171971C265485F1569FF082A30F9B6F578C7"));
        SecurityAssociationSecrets sas = new SecurityAssociationSecrets(DHGroupEnum.GROUP1_768);
        sas.setInboundKeyMaterial(bais);
        sas.setOutboundKeyMaterial(bais);
        ESPTransformIDEnum cipher = ESPTransformIDEnum.AES;
        KeyLengthAttributeEnum keylength = KeyLengthAttributeEnum.L128;
        TunnelMode instance = new TunnelMode(InetAddress.getLocalHost(), InetAddress.getLocalHost(), sas, cipher, keylength, null, 0);
        
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("3FC4F52119015EAF732A8A028E7A8190"), instance.outboundKeyEnc.getEncoded());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("A078477837E80A4FF1D3379CCEF52888"), instance.inboundKeyEnc.getEncoded());
    }
    
    /**
     * Test of rekey method, of class TunnelMode.
     */
    @Test
    public void testRekeyIKEv2WithAuth() throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(DatatypeHelper.hexDumpToByteArray(
                "3FC4F52119015EAF732A8A028E7A8190A078477837E80A4FF1D3379CCEF52888C8613BC2EECBF1A1905CF05284718C63597D516C1B354E66C029B26F171971C265485F1569FF082A30F9B6F578C7"));
        SecurityAssociationSecrets sas = new SecurityAssociationSecrets(DHGroupEnum.GROUP1_768);
        sas.setInboundKeyMaterial(bais);
        sas.setOutboundKeyMaterial(bais);
        ESPTransformIDEnum cipher = ESPTransformIDEnum.AES;
        KeyLengthAttributeEnum keylength = KeyLengthAttributeEnum.L128;
        AuthenticationAlgorithmAttributeEnum authAlgo = AuthenticationAlgorithmAttributeEnum.HMAC_SHA;
        TunnelMode instance = new TunnelMode(InetAddress.getLocalHost(), InetAddress.getLocalHost(), sas, cipher, keylength, authAlgo, 0);
        
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("3FC4F52119015EAF732A8A028E7A8190"), instance.outboundKeyEnc.getEncoded());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("EECBF1A1905CF05284718C63597D516C"), instance.inboundKeyEnc.getEncoded());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("A078477837E80A4FF1D3379CCEF52888C8613BC2"), instance.outboundKeyAuth.getEncoded());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("1B354E66C029B26F171971C265485F1569FF082A"), instance.inboundKeyAuth.getEncoded());
    }
    
}
