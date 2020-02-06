/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.networking;

/**
 * Taken from: TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH Licensed under
 * Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Defines the connection end. Either client or server.
 */
public enum ConnectionEndType {

    CLIENT,
    SERVER;

    public ConnectionEndType getPeer() {
        if (this == CLIENT) {
            return SERVER;
        } else {
            return CLIENT;
        }
    }

}
