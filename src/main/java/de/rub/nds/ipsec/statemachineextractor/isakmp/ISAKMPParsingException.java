/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class ISAKMPParsingException extends Exception {

    /**
     * Creates a new instance of <code>ISAKMPParsingException</code> without
     * detail message.
     */
    public ISAKMPParsingException() {
    }

    /**
     * Constructs an instance of <code>ISAKMPParsingException</code> with the
     * specified detail message.
     *
     * @param msg the detail message.
     */
    public ISAKMPParsingException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>ISAKMPParsingException</code> with the
     * specified inner Throwable.
     *
     * @param cause the inner Throwable.
     */
    public ISAKMPParsingException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs an instance of <code>ISAKMPParsingException</code> with the
     * specified detail message and specified inner Throwable.
     *
     * @param cause the inner Throwable.
     */
    public ISAKMPParsingException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
