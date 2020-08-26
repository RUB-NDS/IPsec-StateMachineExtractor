/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2;

import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv2ParsingException extends GenericIKEParsingException {

    /**
     * Creates a new instance of <code>IKEv2ParsingException</code> without
     * detail message.
     */
    public IKEv2ParsingException() {
    }

    /**
     * Constructs an instance of <code>IKEv2ParsingException</code> with the
     * specified detail message.
     *
     * @param msg the detail message.
     */
    public IKEv2ParsingException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>IKEv2ParsingException</code> with the
     * specified inner Throwable.
     *
     * @param cause the inner Throwable.
     */
    public IKEv2ParsingException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs an instance of <code>IKEv2ParsingException</code> with the
     * specified detail message and specified inner Throwable.
     *
     * @param msg the detail message.
     * @param cause the inner Throwable.
     */
    public IKEv2ParsingException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
