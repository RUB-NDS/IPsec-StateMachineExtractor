/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.learning;

import net.automatalib.words.impl.SimpleAlphabet;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEOutputAlphabet extends SimpleAlphabet<String> {

    public static final String NO_RESPONSE = "NO_RESPONSE";
    public static final String PARSING_ERROR = "PARSING_ERROR";

    private static IKEOutputAlphabet instance;

    private IKEOutputAlphabet() {
        super();
        this.add(NO_RESPONSE);
        this.add(PARSING_ERROR);
    }

    public static IKEOutputAlphabet get() {
        if (instance == null) {
            instance = new IKEOutputAlphabet();
        }
        return instance;
    }

}
