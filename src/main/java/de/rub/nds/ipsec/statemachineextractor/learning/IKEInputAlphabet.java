/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.learning;

import net.automatalib.words.impl.ArrayAlphabet;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEInputAlphabet extends ArrayAlphabet<String> {

    public IKEInputAlphabet() {
        super((new String[]{
            "RESET",
            "v1_MM_PSK-SA",
            "v1_MM_KE-No",
            "v1_MM*_ID-HASH",
            "v1_AM_PSK-SA-KE-No-ID",
            "v1_AM_HASH",
            "v1_QM*_HASH1-SA-No",
        }));
    }

}
