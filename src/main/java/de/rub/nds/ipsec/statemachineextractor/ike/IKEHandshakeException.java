/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEHandshakeException extends GenericIKEParsingException {

    /**
     * Creates a new instance of <code>IKEHandshakeException</code> without
     * detail message.
     */
    public IKEHandshakeException() {
    }

    /**
     * Constructs an instance of <code>IKEHandshakeException</code> with the
     * specified detail message.
     *
     * @param msg the detail message.
     */
    public IKEHandshakeException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>IKEHandshakeException</code> with the
     * specified inner Throwable.
     *
     * @param cause the inner Throwable.
     */
    public IKEHandshakeException(Throwable cause) {
        super(cause);
    }
    
}
