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
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Handshake;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import java.net.InetAddress;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEMessageMapperTest {

    static {
        CryptoHelper.prepare();
    }

    @Test
    @Ignore
    public void testMapInputMapOutput() throws Exception {
        String abstractInput, abstractOutput;
        ContextExecutableInput<ISAKMPMessage, IKEv1Handshake> executableInput;
        ISAKMPMessage concreteOutput;
        IKEMessageMapper instance = new IKEMessageMapper();
        IKEv1Handshake handshake = new IKEv1Handshake(2000, InetAddress.getByName("134.147.198.14"), 500);

        abstractInput = "v1_MM_RPKE-SA";
        executableInput = instance.mapInput(abstractInput);
        concreteOutput = executableInput.execute(handshake);
        abstractOutput = instance.mapOutput(concreteOutput);
        assertEquals("v1_MM_SA-V", abstractOutput);

        abstractInput = "v1_MM_<No>-(KE)-(ID)";
        executableInput = instance.mapInput(abstractInput);
        concreteOutput = executableInput.execute(handshake);
        abstractOutput = instance.mapOutput(concreteOutput);
        assertEquals("NO_RESPONSE", abstractOutput);

//        abstractInput = "v1_QM*_HASH1-SA-No-IDci-IDcr";
//        executableInput = instance.mapInput(abstractInput);
//        concreteOutput = executableInput.execute(handshake);
//        abstractOutput = instance.mapOutput(concreteOutput);
//        assertEquals("v1_QM*-HASH-SA-No-ID-ID-ResponderLifetime", abstractOutput);
//
//        abstractInput = "v1_QM*_HASH3";
//        executableInput = instance.mapInput(abstractInput);
//        concreteOutput = executableInput.execute(handshake);
//        abstractOutput = instance.mapOutput(concreteOutput);
//        assertEquals("NO_RESPONSE", abstractOutput);
//
//        abstractInput = "v1_INFO*_HASH1-DEL";
//        executableInput = instance.mapInput(abstractInput);
//        concreteOutput = executableInput.execute(handshake);
//        abstractOutput = instance.mapOutput(concreteOutput);
//        assertEquals("v1_INFO*-HASH-DEL", abstractOutput);
    }

}
