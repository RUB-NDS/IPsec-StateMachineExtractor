/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor;

import de.learnlib.algorithms.dhc.mealy.MealyDHC;
import de.learnlib.api.oracle.MembershipOracle;
import de.learnlib.api.query.DefaultQuery;
import de.learnlib.examples.mealy.ExampleCoffeeMachine;
import de.learnlib.examples.mealy.ExampleCoffeeMachine.Input;
import de.learnlib.filter.cache.mealy.MealyCaches;
import de.learnlib.oracle.equivalence.SimulatorEQOracle;
import de.learnlib.oracle.membership.SimulatorOracle;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.automatalib.automata.transout.impl.compact.CompactMealy;
import net.automatalib.serialization.dot.GraphDOT;
import net.automatalib.words.Alphabet;
import net.automatalib.words.Word;

/**
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class Main {

    public static void main(String[] args) {
        CompactMealy<Input, String> fm = ExampleCoffeeMachine.constructMachine();
        Alphabet<Input> alphabet = fm.getInputAlphabet();

        SimulatorOracle<Input, Word<String>> simoracle = new SimulatorOracle<>(fm);
        SimulatorEQOracle<Input, Word<String>> eqoracle = new SimulatorEQOracle<>(fm);

        MembershipOracle<Input, Word<String>> cache = MealyCaches.createCache(alphabet, simoracle);

        MealyDHC<Input, String> learner = new MealyDHC<>(alphabet, cache);

        DefaultQuery<Input, Word<String>> counterexample = null;
        do {
            if (counterexample == null) {
                learner.startLearning();
            } else {
                boolean refined = learner.refineHypothesis(counterexample);
                if (!refined) {
                    System.err.println("No refinement effected by counterexample!");
                }
            }
            counterexample = eqoracle.findCounterExample(learner.getHypothesisModel(), alphabet);
        } while (counterexample != null);
        CompactMealy<Input, String> hypothesisModel = learner.getHypothesisModel();
        try {
            writeDotModel(hypothesisModel, "test.dot");
        } catch (IOException | InterruptedException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static void writeDotModel(CompactMealy<Input, String> model, String filename) throws IOException, InterruptedException {
		File dotFile = new File(filename);
        try (PrintStream psDotFile = new PrintStream(dotFile)) {
            GraphDOT.write(model, psDotFile);
        }
		Runtime.getRuntime().exec("dot -Tpdf -O " + filename);
	}
}
