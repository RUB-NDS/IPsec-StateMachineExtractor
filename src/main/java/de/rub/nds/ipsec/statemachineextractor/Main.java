/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor;

import de.rub.nds.ipsec.statemachineextractor.learning.IKEMessageMapper;
import de.learnlib.algorithms.lstar.mealy.ExtensibleLStarMealyBuilder;
import de.learnlib.api.query.DefaultQuery;
import de.rub.nds.ipsec.statemachineextractor.learning.IKEAlphabetEnum;
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
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Handshake;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.learning.IKEv1HandshakeContextHandler;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.net.UnknownHostException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.automatalib.serialization.dot.GraphDOT;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class Main {
    
    static {
        UnlimitedStrengthEnabler.enable();
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    private static final long timeout = 100;
    private static final String host = "10.0.3.2";
    private static final int port = 500;
    
    public static void main(String[] args) throws UnknownHostException {
        Instant instant = Instant.now();
        Alphabet<IKEAlphabetEnum> alphabet = Alphabets.fromEnum(IKEAlphabetEnum.class);
        final IKEv1HandshakeContextHandler contextHandler = new IKEv1HandshakeContextHandler(timeout, host, port);
        final ContextExecutableInputSUL<ContextExecutableInput<ISAKMPMessage, IKEv1Handshake>, ISAKMPMessage, IKEv1Handshake> ceiSUL;
        ceiSUL = new ContextExecutableInputSUL<>(contextHandler);
        SUL<IKEAlphabetEnum, IKEAlphabetEnum> sul = SULMappers.apply(new IKEMessageMapper(), ceiSUL);
        SULOracle<IKEAlphabetEnum, IKEAlphabetEnum> oracle = new SULOracle<>(sul);
        MealyCacheOracle<IKEAlphabetEnum, IKEAlphabetEnum> mqOracle = MealyCacheOracle.createDAGCacheOracle(alphabet, null, oracle);

        MealyLearner<IKEAlphabetEnum, IKEAlphabetEnum> learner;
        learner = new ExtensibleLStarMealyBuilder<IKEAlphabetEnum, IKEAlphabetEnum>().withAlphabet(alphabet).withOracle(mqOracle).create();

        learner.startLearning();
        MealyMachine<?, IKEAlphabetEnum, ?, IKEAlphabetEnum> hypothesis = learner.getHypothesisModel();

        MealyEquivalenceOracle<IKEAlphabetEnum, IKEAlphabetEnum> eqOracle = new MealyRandomWordsEQOracle<>(
                mqOracle,
                1, // minLength
                4, //maxLength
                50, // maxTests
                new Random(1));

        DefaultQuery<IKEAlphabetEnum, Word<IKEAlphabetEnum>> ce;
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
