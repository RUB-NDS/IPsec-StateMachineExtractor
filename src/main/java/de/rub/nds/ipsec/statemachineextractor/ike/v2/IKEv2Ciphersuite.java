/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2;

import de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.PRFAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.CipherAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.DHGroupAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.IntegrityAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.KeyLengthAttributeEnum;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv2Ciphersuite extends IKEv1Ciphersuite {
	
	
	// Here check if need to change some major values from alle the v1.attributes...

}
