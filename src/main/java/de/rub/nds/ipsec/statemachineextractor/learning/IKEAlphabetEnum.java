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
public enum IKEAlphabetEnum {
    NO_RESPONSE,
    IKEv1_MM_SA_PKE,
    IKEv1_MM_KEX_PKE,
    IKEv1_MM_HASH;
}
