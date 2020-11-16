/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.learning;

import de.learnlib.mapper.api.ContextExecutableInput;
import de.rub.nds.ipsec.statemachineextractor.SerializableMessage;
import de.rub.nds.ipsec.statemachineextractor.ipsec.IPsecConnection;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import java.net.InetAddress;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.junit.Assert.assertEquals;
import org.junit.Ignore;
import org.junit.Test;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IPsecMessageMapperTest {

    static {
        CryptoHelper.prepare();
    }

    @Test
    @Ignore
    public void testMapInputMapOutputCiscoPSKAM() throws Exception {
        try {
            String abstractInput, abstractOutput;
            ContextExecutableInput<SerializableMessage, IPsecConnection> executableInput;
            SerializableMessage concreteOutput;
            IPsecMessageMapper instance = new IPsecMessageMapper();
            IPsecConnection conn = new IPsecConnection(InetAddress.getByName("10.0.3.2"), 500, 2000);

            abstractInput = "v1_AM_PSK-SA-KE-No-ID";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_AM_SA-V-V-V-V-KE-ID-No-HASH", abstractOutput);

            abstractInput = "v1_AM_HASH";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("NO_RESPONSE", abstractOutput);

            abstractInput = "v1_QM*_HASH1-SA-No-IDci-IDcr";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_QM*_HASH-SA-No-ID-ID-ResponderLifetime", abstractOutput);

            abstractInput = "v1_QM*_HASH3";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("NO_RESPONSE", abstractOutput);

            abstractInput = "ESP_IPv4_TCP_SYN_SSH";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("ESP_IPv4_TCP_SYNACK", abstractOutput);
        } catch (Exception ex) {
            Logger.getLogger(IPsecMessageMapperTest.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        }
    }

    @Test
    @Ignore
    public void testMapInputMapOutputCiscoPSKMM() throws Exception {
        try {
            String abstractInput, abstractOutput;
            ContextExecutableInput<SerializableMessage, IPsecConnection> executableInput;
            SerializableMessage concreteOutput;
            IPsecMessageMapper instance = new IPsecMessageMapper();
            IPsecConnection conn = new IPsecConnection(InetAddress.getByName("10.0.3.2"), 500, 2000);

            abstractInput = "v1_MM_PSK-SA";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_MM_SA", abstractOutput);

            abstractInput = "v1_MM_KE-No";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_MM_KE-No-V-V-V-V", abstractOutput);

            abstractInput = "v1_MM*_ID-HASH";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_MM*_ID-HASH", abstractOutput);

            abstractInput = "v1_QM*_HASH1-SA-No-IDci-IDcr";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_QM*_HASH-SA-No-ID-ID-ResponderLifetime", abstractOutput);

            abstractInput = "v1_QM*_HASH3";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("NO_RESPONSE", abstractOutput);

            abstractInput = "ESP_IPv4_TCP_SYN_SSH";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("ESP_IPv4_TCP_SYNACK", abstractOutput);
        } catch (Exception ex) {
            Logger.getLogger(IPsecMessageMapperTest.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        }
    }

    @Test
    @Ignore
    public void testMapInputMapOutputCiscoPKEMM() throws Exception {
        try {
            String abstractInput, abstractOutput;
            ContextExecutableInput<SerializableMessage, IPsecConnection> executableInput;
            SerializableMessage concreteOutput;
            IPsecMessageMapper instance = new IPsecMessageMapper();
            IPsecConnection conn = new IPsecConnection(InetAddress.getByName("10.0.3.2"), 500, 2000);

            abstractInput = "v1_MM_PKE-SA";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_MM_SA", abstractOutput);

            abstractInput = "v1_MM_KE-<ID>-<No>";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_MM_KE-<ID>-<No>-V-V-V-V", abstractOutput);

            abstractInput = "v1_MM*_HASH";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_MM*_HASH", abstractOutput);

            abstractInput = "v1_QM*_HASH1-SA-No-IDci-IDcr";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_QM*_HASH-SA-No-ID-ID-ResponderLifetime", abstractOutput);

            abstractInput = "v1_QM*_HASH3";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("NO_RESPONSE", abstractOutput);

            abstractInput = "ESP_IPv4_TCP_SYN_SSH";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("ESP_IPv4_TCP_SYNACK", abstractOutput);
        } catch (Exception ex) {
            Logger.getLogger(IPsecMessageMapperTest.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        }
    }

    @Test
    @Ignore
    public void testMapInputMapOutputIKEv1() throws Exception {
        try {
            String abstractInput, abstractOutput;
            ContextExecutableInput<SerializableMessage, IPsecConnection> executableInput;
            SerializableMessage concreteOutput;
            IPsecMessageMapper instance = new IPsecMessageMapper();
            IPsecConnection conn = new IPsecConnection(InetAddress.getByName("10.0.3.10"), 500, 2000);

            abstractInput = "v1_MM_PSK-SA";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_MM_SA-V-V", abstractOutput);

            abstractInput = "v1_MM_KE-No";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_MM_KE-No", abstractOutput);

            abstractInput = "v1_MM*_ID-HASH";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_MM*_ID-HASH", abstractOutput);

            abstractInput = "v1_QM*_HASH1-SA-No-IDci-IDcr";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_QM*_HASH-SA-No-ID-ID", abstractOutput);

            abstractInput = "v1_QM*_HASH3";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("NO_RESPONSE", abstractOutput);

            abstractInput = "ESP_IPv4_TCP_SYN_SSH";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("ESP_IPv4_TCP_SYNACK", abstractOutput);

            abstractInput = "ESP_IPv4_TCP_SYN_SSH";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("ESP_IPv4_TCP_SYNACK", abstractOutput);
        } catch (Exception ex) {
            Logger.getLogger(IPsecMessageMapperTest.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        }
    }

    @Test
    @Ignore
    public void testMapInputMapOutputIKEv2() throws Exception {
        try {
            String abstractInput, abstractOutput;
            ContextExecutableInput<SerializableMessage, IPsecConnection> executableInput;
            SerializableMessage concreteOutput;
            IPsecMessageMapper instance = new IPsecMessageMapper();
            IPsecConnection conn = new IPsecConnection(InetAddress.getByName("10.0.3.10"), 500, 2000);

            abstractInput = "v2_SAINIT_PSK-SA-KE-No";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v2_SAINIT_SA-KE-No-MultipleAuthSupport", abstractOutput);

            abstractInput = "v2_AUTH_PSK-IDi-AUTH-SA-TSi-TSr";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v2_AUTH_IDr-AUTH-SA-TSi-TSr", abstractOutput);

            abstractInput = "ESP_IPv4_TCP_SYN_SSH";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(conn);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("ESP_IPv4_TCP_SYNACK", abstractOutput);
        } catch (Exception ex) {
            Logger.getLogger(IPsecMessageMapperTest.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        }
    }
}
