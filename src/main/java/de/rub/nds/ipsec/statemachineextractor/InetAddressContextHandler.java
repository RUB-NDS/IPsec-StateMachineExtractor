/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor;

import de.learnlib.mapper.ContextExecutableInputSUL.ContextHandler;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class InetAddressContextHandler implements ContextHandler<InetAddress> {

    private final InetAddress context;
    
    public InetAddressContextHandler(byte[] addr) throws UnknownHostException {
        context = InetAddress.getByAddress(addr);
    }
    
    public InetAddressContextHandler(String host) throws UnknownHostException {
        context = InetAddress.getByName(host);
    }

    /** {@inheritDoc} */
    @Override
    public InetAddress createContext() {
        return context;
    }

    /** {@inheritDoc} */
    @Override
    public void disposeContext(InetAddress c) {
    }
}
