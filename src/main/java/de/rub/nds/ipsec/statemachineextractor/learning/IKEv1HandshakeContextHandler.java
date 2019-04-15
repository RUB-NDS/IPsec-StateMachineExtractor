/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.learning;

import de.learnlib.mapper.ContextExecutableInputSUL.ContextHandler;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Handshake;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1HandshakeContextHandler implements ContextHandler<IKEv1Handshake> {

    private final long timeout;
    private final int port;
    private final InetAddress remoteAddress;

    private IKEv1HandshakeContextHandler(long timeout, InetAddress addr, int port) throws UnknownHostException {
        this.timeout = timeout;
        this.port = port;
        this.remoteAddress = addr;
    }
    
    public IKEv1HandshakeContextHandler(long timeout, byte[] addr, int port) throws UnknownHostException {
        this(timeout, InetAddress.getByAddress(addr), port);
    }
    
    public IKEv1HandshakeContextHandler(long timeout, String host, int port) throws UnknownHostException {
        this(timeout, InetAddress.getByName(host), port);
    }
    
    /** {@inheritDoc} */
    @Override
    public IKEv1Handshake createContext() {
        return new IKEv1Handshake(timeout, remoteAddress, port);
    }

    /** {@inheritDoc} */
    @Override
    public void disposeContext(IKEv1Handshake c) {
        try {
            c.dispose();
        } catch (IOException ex) {
            Logger.getLogger(IKEv1HandshakeContextHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
