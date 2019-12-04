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

    private final long timeout;
    private final int port;
    private final InetAddress remoteAddress;

    private IPsecConnectionContextHandler(long timeout, InetAddress addr, int port) throws UnknownHostException {
        this.timeout = timeout;
        this.port = port;
        this.remoteAddress = addr;
    }

    public IPsecConnectionContextHandler(long timeout, byte[] addr, int port) throws UnknownHostException {
        this(timeout, InetAddress.getByAddress(addr), port);
    }

    public IPsecConnectionContextHandler(long timeout, String host, int port) throws UnknownHostException {
        this(timeout, InetAddress.getByName(host), port);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public IPsecConnection createContext() {
        try {
            return new IPsecConnection(timeout, remoteAddress, port);
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
