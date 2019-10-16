/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.learning;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum IKEInputAlphabetEnum {
    RESET,
    RETRANS,
    v1_MM_PSK_SA,
    v1_MM_PSK_KE_No,
    v1_MM_PSK_ID_HASH,
    v1_AM_PSK_SA_KE_No_ID,
    v1_AM_HASH;
}
