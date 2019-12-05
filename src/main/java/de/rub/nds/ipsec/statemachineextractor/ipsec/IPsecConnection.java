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
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.DHGroupAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProtocolIDEnum;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.GeneralSecurityException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public final class IPsecConnection {

    private IKEv1Handshake handshake;
    private final int timeout;
    private final InetAddress localAddress, remoteAddress;
    private final int remotePort;
    private SecurityAssociationSecrets SA;

    public IPsecConnection(InetAddress remoteAddress, int remotePort, int timeout) throws IOException, GeneralSecurityException {
        this.timeout = timeout;
        this.remoteAddress = remoteAddress;
        try (final DatagramSocket socket = new DatagramSocket()) {
            socket.connect(remoteAddress, remotePort);
            this.localAddress = socket.getLocalAddress();
        }
        this.remotePort = remotePort;
        this.handshake = new IKEv1Handshake(timeout, remoteAddress, remotePort);
        this.SA = new SecurityAssociationSecrets(DHGroupAttributeEnum.GROUP1);
        this.SA.setProtocol(ProtocolIDEnum.IPSEC_ESP);
        this.handshake.computeIPsecKeyMaterial(this.SA);
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
