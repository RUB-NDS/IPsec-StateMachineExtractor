/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor;

import de.rub.nds.ipsec.statemachineextractor.learning.IPsecMessageMapper;
import de.learnlib.algorithms.lstar.mealy.ExtensibleLStarMealyBuilder;
import de.learnlib.api.query.DefaultQuery;
import java.time.Duration;
import java.time.Instant;
import java.util.Random;

import net.automatalib.automata.transout.MealyMachine;
import net.automatalib.words.Alphabet;
import net.automatalib.words.Word;
import de.learnlib.api.SUL;
import de.learnlib.api.algorithm.LearningAlgorithm.MealyLearner;
import de.learnlib.api.oracle.EquivalenceOracle.MealyEquivalenceOracle;
import de.learnlib.filter.cache.mealy.MealyCacheOracle;
import de.learnlib.mapper.ContextExecutableInputSUL;
import de.learnlib.mapper.SULMappers;
import de.learnlib.mapper.api.ContextExecutableInput;
import de.learnlib.oracle.equivalence.RandomWordsEQOracle.MealyRandomWordsEQOracle;
import de.learnlib.oracle.membership.SULOracle;
import de.rub.nds.ipsec.statemachineextractor.ipsec.IPsecConnection;
import de.rub.nds.ipsec.statemachineextractor.learning.IPsecInputAlphabet;
import de.rub.nds.ipsec.statemachineextractor.learning.IPsecConnectionContextHandler;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.automatalib.serialization.dot.GraphDOT;

/**
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class Main {

    static {
        CryptoHelper.prepare();
    }

    private static final int timeout = 600;
    private static final String host = "10.0.3.2";
    private static final int port = 500;

    public static void main(String[] args) throws UnknownHostException {
        Instant instant = Instant.now();
        IPsecInputAlphabet inputAlphabet = new IPsecInputAlphabet();
        final IPsecConnectionContextHandler contextHandler = new IPsecConnectionContextHandler(host, port, timeout);
        final ContextExecutableInputSUL<ContextExecutableInput<SerializableMessage, IPsecConnection>, SerializableMessage, IPsecConnection> ceiSUL;
        ceiSUL = new ContextExecutableInputSUL<>(contextHandler);
        SUL<String, String> sul = SULMappers.apply(new IPsecMessageMapper(), ceiSUL);
        SULOracle<String, String> oracle = new SULOracle<>(sul);
        MealyCacheOracle<String, String> mqOracle = MealyCacheOracle.createDAGCacheOracle(inputAlphabet, oracle);

        MealyLearner<String, String> learner;
        learner = new ExtensibleLStarMealyBuilder<String, String>().withAlphabet(inputAlphabet).withOracle(mqOracle).create();

        learner.startLearning();
        MealyMachine<?, String, ?, String> hypothesis = learner.getHypothesisModel();

        MealyEquivalenceOracle<String, String> eqOracle = new MealyRandomWordsEQOracle<>(
                mqOracle,
                1, // minLength
                4, //maxLength
                50, // maxTests
                new Random(1));

        DefaultQuery<String, Word<String>> ce;
        while ((ce = eqOracle.findCounterExample(hypothesis, inputAlphabet)) != null) {
            System.err.println("Found counterexample " + ce);
            System.err.println("Current hypothesis has " + hypothesis.getStates().size() + " states");

            learner.refineHypothesis(ce);
            hypothesis = learner.getHypothesisModel();
        }
        System.err.println("Final hypothesis has " + hypothesis.getStates().size() + " states");

        Instant end = Instant.now();
        Duration duration = Duration.between(instant, end);
        System.err.println("duration " + duration);

        try {
            writeDotModel(hypothesis, inputAlphabet, "test.dot");
        } catch (IOException | InterruptedException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static <I> void writeDotModel(MealyMachine<?, I, ?, ?> model, Alphabet<I> alphabet, String filename) throws IOException, InterruptedException {
        MealyMachine.MealyGraphView mealyGraphView = new MealyMachine.MealyGraphView(model, alphabet);
        File dotFile = new File(filename);
        try (PrintStream psDotFile = new PrintStream(dotFile)) {
            GraphDOT.write(mealyGraphView, psDotFile);
        }
        Runtime.getRuntime().exec("dot -Tpdf -O " + filename); // requires graphviz
    }
}
