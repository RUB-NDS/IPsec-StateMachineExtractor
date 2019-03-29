/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ikev1;

import de.learnlib.mapper.api.ContextExecutableInput;
import de.learnlib.mapper.api.SULMapper;
import java.net.InetAddress;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1MessageMapper implements SULMapper<IKEv1MessageEnum, IKEv1MessageEnum, ContextExecutableInput<ISAKMPMessage, InetAddress>, ISAKMPMessage> {

    @Override
    public ContextExecutableInput<ISAKMPMessage, InetAddress> mapInput(IKEv1MessageEnum abstractInput) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public IKEv1MessageEnum mapOutput(ISAKMPMessage concreteOutput) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
        
}
