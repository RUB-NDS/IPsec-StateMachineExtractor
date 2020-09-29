/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import java.security.GeneralSecurityException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public interface EncryptedIKEData {

    void decrypt() throws GeneralSecurityException, GenericIKEParsingException;

    void encrypt() throws GeneralSecurityException;

    byte[] getCiphertext();

    boolean isInSync();
    
}
