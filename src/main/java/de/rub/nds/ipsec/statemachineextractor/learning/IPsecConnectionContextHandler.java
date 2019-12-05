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
import de.rub.nds.ipsec.statemachineextractor.ipsec.IPsecConnection;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IPsecConnectionContextHandler implements ContextHandler<IPsecConnection> {

    private final int timeout;
    private final int port;
    private final InetAddress remoteAddress;

    private IPsecConnectionContextHandler(InetAddress addr, int port, int timeout) throws UnknownHostException {
        this.timeout = timeout;
        this.port = port;
        this.remoteAddress = addr;
    }

    public IPsecConnectionContextHandler(byte[] addr, int port, int timeout) throws UnknownHostException {
        this(InetAddress.getByAddress(addr), port, timeout);
    }

    public IPsecConnectionContextHandler(String host, int port, int timeout) throws UnknownHostException {
        this(InetAddress.getByName(host), port, timeout);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public IPsecConnection createContext() {
        try {
            return new IPsecConnection(remoteAddress, port, timeout);
        } catch (IOException | GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void disposeContext(IPsecConnection c) {
        try {
            c.dispose();
        } catch (IOException ex) {
            Logger.getLogger(IPsecConnectionContextHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
