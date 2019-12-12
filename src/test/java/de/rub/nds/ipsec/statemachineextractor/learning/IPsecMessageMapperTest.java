/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
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
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

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
    public void testMapInputMapOutput() throws Exception {
        String abstractInput, abstractOutput;
        ContextExecutableInput<SerializableMessage, IPsecConnection> executableInput;
        SerializableMessage concreteOutput;
        IPsecMessageMapper instance = new IPsecMessageMapper();
        IPsecConnection conn = new IPsecConnection(InetAddress.getByName("10.0.3.10"), 500, 600);

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

        abstractInput = "ESP_IPv4_TCP_SYN";
        executableInput = instance.mapInput(abstractInput);
        concreteOutput = executableInput.execute(conn);
        abstractOutput = instance.mapOutput(concreteOutput);
        assertEquals("ESP_IPv4_TCP_SYNACK", abstractOutput);
    }

}
