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
public class GenericIKEParsingException extends Exception {

    /**
     * Creates a new instance of <code>GenericIKEParsingException</code> without
     * detail message.
     */
    public GenericIKEParsingException() {
    }

    /**
     * Constructs an instance of <code>GenericIKEParsingException</code> with
     * the specified detail message.
     *
     * @param msg the detail message.
     */
    public GenericIKEParsingException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>GenericIKEParsingException</code> with
     * the specified inner Throwable.
     *
     * @param cause the inner Throwable.
     */
    public GenericIKEParsingException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs an instance of <code>GenericIKEParsingException</code> with
     * the specified detail message and specified inner Throwable.
     *
     * @param cause the inner Throwable.
     */
    public GenericIKEParsingException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
