/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.learning;

import java.util.Arrays;
import net.automatalib.words.Alphabet;
import net.automatalib.words.impl.Alphabets;
import net.automatalib.words.impl.ArrayAlphabet;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEInputAlphabet extends ArrayAlphabet<String> {

    public static final Alphabet<String> alphabet = Alphabets.fromArray();

    public IKEInputAlphabet() {
        this.addAll(Arrays.asList(new String[]{
            "RESET",
            "v1_MM_PSK-SA",
            "v1_MM-KE-No",
            "v1_MM*-ID-HASH",
            "v1_AM_PSK-SA-KE-No-ID",
            "v1_AM-HASH"}));
    }

}
