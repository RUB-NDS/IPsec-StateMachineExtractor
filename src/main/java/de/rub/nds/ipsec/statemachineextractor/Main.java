/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor;

import de.learnlib.algorithms.lstar.mealy.ExtensibleLStarMealyBuilder;
import de.learnlib.api.query.DefaultQuery;
import de.rub.nds.ipsec.statemachineextractor.ikev1.IKEv1MessageEnum;
import java.time.Duration;
import java.time.Instant;
import java.util.Random;

import net.automatalib.automata.transout.MealyMachine;
import net.automatalib.words.Alphabet;
import net.automatalib.words.Word;
import net.automatalib.words.impl.Alphabets;
import de.learnlib.api.SUL;
import de.learnlib.api.algorithm.LearningAlgorithm.MealyLearner;
import de.learnlib.api.oracle.EquivalenceOracle.MealyEquivalenceOracle;
import de.learnlib.filter.cache.mealy.MealyCacheOracle;
import de.learnlib.mapper.ContextExecutableInputSUL;
import de.learnlib.mapper.SULMappers;
import de.learnlib.mapper.api.ContextExecutableInput;
import de.learnlib.oracle.equivalence.RandomWordsEQOracle.MealyRandomWordsEQOracle;
import de.learnlib.oracle.membership.SULOracle;
import de.rub.nds.ipsec.statemachineextractor.ikev1.IKEv1MessageMapper;
import de.rub.nds.ipsec.statemachineextractor.ikev1.ISAKMPMessage;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.automatalib.serialization.dot.GraphDOT;

/**
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class Main {

    public static void main(String[] args) throws UnknownHostException {
        Instant instant = Instant.now();
        Alphabet<IKEv1MessageEnum> alphabet = Alphabets.fromEnum(IKEv1MessageEnum.class);
        final InetAddressContextHandler contextHandler = new InetAddressContextHandler("10.0.3.4");
        final ContextExecutableInputSUL<ContextExecutableInput<ISAKMPMessage, InetAddress>, ISAKMPMessage, InetAddress> ceiSUL;
        ceiSUL = new ContextExecutableInputSUL<>(contextHandler);
        SUL<IKEv1MessageEnum, IKEv1MessageEnum> sul = SULMappers.apply(new IKEv1MessageMapper(), ceiSUL);
        SULOracle<IKEv1MessageEnum, IKEv1MessageEnum> oracle = new SULOracle<>(sul);
        MealyCacheOracle<IKEv1MessageEnum, IKEv1MessageEnum> mqOracle = MealyCacheOracle.createDAGCacheOracle(alphabet, null, oracle);

        MealyLearner<IKEv1MessageEnum, IKEv1MessageEnum> learner;
        learner = new ExtensibleLStarMealyBuilder<IKEv1MessageEnum, IKEv1MessageEnum>().withAlphabet(alphabet).withOracle(mqOracle).create();

        learner.startLearning();
        MealyMachine<?, IKEv1MessageEnum, ?, IKEv1MessageEnum> hypothesis = learner.getHypothesisModel();

        MealyEquivalenceOracle<IKEv1MessageEnum, IKEv1MessageEnum> eqOracle = new MealyRandomWordsEQOracle<>(
                mqOracle,
                1, // minLength
                4, //maxLength
                50, // maxTests
                new Random(1));

        DefaultQuery<IKEv1MessageEnum, Word<IKEv1MessageEnum>> ce;
        while ((ce = eqOracle.findCounterExample(hypothesis, alphabet)) != null) {
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
            writeDotModel(hypothesis, alphabet, "test.dot");
        } catch (IOException | InterruptedException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static <I> void writeDotModel(MealyMachine<?, I, ?, I> model, Alphabet<I> alphabet, String filename) throws IOException, InterruptedException {
        MealyMachine.MealyGraphView mealyGraphView = new MealyMachine.MealyGraphView(model, alphabet);
        File dotFile = new File(filename);
        try (PrintStream psDotFile = new PrintStream(dotFile)) {
            GraphDOT.write(mealyGraphView, psDotFile);
        }
        Runtime.getRuntime().exec("dot -Tpdf -O " + filename);
    }
}
