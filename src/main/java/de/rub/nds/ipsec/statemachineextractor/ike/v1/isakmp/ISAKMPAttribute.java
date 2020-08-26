/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEAttribute;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public interface ISAKMPAttribute extends GenericIKEAttribute, ISAKMPSerializable {

    public void configureCiphersuite(IKEv1Ciphersuite ciphersuite);

}
