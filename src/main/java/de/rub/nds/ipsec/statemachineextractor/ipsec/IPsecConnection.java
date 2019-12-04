/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Handshake;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.SecurityAssociationSecrets;
import java.io.IOException;
import java.net.InetAddress;
import java.security.GeneralSecurityException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public final class IPsecConnection {

    private IKEv1Handshake handshake;
    private final long timeout;
    private final InetAddress remoteAddress;
    private final int remotePort;
    private SecurityAssociationSecrets SA;

    public IPsecConnection(long timeout, InetAddress remoteAddress, int remotePort) throws IOException, GeneralSecurityException {
        this.timeout = timeout;
        this.remoteAddress = remoteAddress;
        this.remotePort = remotePort;
        this.handshake = new IKEv1Handshake(timeout, remoteAddress, remotePort);
    }

    public void dispose() throws IOException {
        this.handshake.dispose();
    }

    public void reset() throws IOException, GeneralSecurityException {
        this.dispose();
        this.handshake = new IKEv1Handshake(timeout, remoteAddress, remotePort);
    }

    public IKEv1Handshake getHandshake() {
        return handshake;
    }

    public SecurityAssociationSecrets getSA() {
        return SA;
    }

    public void setSA(SecurityAssociationSecrets SA) {
        this.SA = SA;
    }
}
