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
public class IPsecInputAlphabet extends ArrayAlphabet<String> {

    public IPsecInputAlphabet() {
        super((new String[]{
            "RESET",
            "NEW_QM_MSG_ID",
            
            "v1_MM_PSK-SA",
            "v1_MM_PKE-SA",
            "v1_MM_KE",
            "v1_MM_No",
            "v1_MM_ID",
            "v1_MM_KE-No",
            "v1_MM_KE-ID",
            "v1_MM_ID-KE",
            "v1_MM_No-KE",
            "v1_MM_KE-No-ID",
            "v1_MM_No-ID-KE",
            "v1_MM_ID-KE-No",
            "v1_MM*_ID",
            "v1_MM*_HASH",
            "v1_MM*_ID-HASH",
            "v1_MM*_HASH-ID",
            
            "v1_AM_PSK-SA-KE-No-ID",
            "v1_AM_PSK-SA-KE-No",
            "v1_AM_PSK-SA-KE-ID",
            "v1_AM_PSK-SA-KE",
            "v1_AM_PSK-SA-No-ID",
            "v1_AM_PSK-SA-No",
            "v1_AM_PSK-SA-ID",
            "v1_AM_PSK-SA",
            "v1_AM_HASH",
            
            "v1_QM*_HASH1-SA-No-IDci-IDcr",
            "v1_QM*_HASH3",

            "v1_INFO*_DEL",
            
            "ESP_IPv4_TCP_SYN_SSH",
        }));
    }

}
