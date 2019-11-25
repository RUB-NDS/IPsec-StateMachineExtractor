package de.rub.nds.ipsec.statemachineextractor.learning;

import de.learnlib.mapper.api.ContextExecutableInput;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Handshake;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import java.net.InetAddress;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEMessageMapperTest {

    static {
        CryptoHelper.prepare();
    }

    @Test
    public void testMapInputMapOutput() throws Exception {
        while (true) {
//        {
            String abstractInput, abstractOutput;
            ContextExecutableInput<ISAKMPMessage, IKEv1Handshake> executableInput;
            ISAKMPMessage concreteOutput;
            IKEMessageMapper instance = new IKEMessageMapper();
            IKEv1Handshake handshake = new IKEv1Handshake(1000, InetAddress.getByName("10.0.3.2"), 500);

            abstractInput = "v1_AM_PSK-SA-KE-No-ID";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(handshake);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_AM-SA-V-V-V-V-KE-ID-No-HASH", abstractOutput);

            abstractInput = "v1_AM_HASH";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(handshake);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("NO_RESPONSE", abstractOutput);

            abstractInput = "v1_QM*_HASH1-SA-No-IDci-IDcr";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(handshake);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_QM*-HASH-SA-No-ID-ID-ResponderLifetime", abstractOutput);

            abstractInput = "v1_QM*_HASH3";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(handshake);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("NO_RESPONSE", abstractOutput);

            abstractInput = "v1_INFO*_HASH1-DEL";
            executableInput = instance.mapInput(abstractInput);
            concreteOutput = executableInput.execute(handshake);
            abstractOutput = instance.mapOutput(concreteOutput);
            assertEquals("v1_INFO*-HASH-DEL", abstractOutput);
        }
    }

}
