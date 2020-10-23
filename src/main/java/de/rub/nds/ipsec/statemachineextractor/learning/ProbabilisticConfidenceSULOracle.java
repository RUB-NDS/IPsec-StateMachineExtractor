/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.learning;

import de.learnlib.api.SUL;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map.Entry;

import de.learnlib.api.query.Query;
import de.learnlib.oracle.membership.SULOracle;
import net.automatalib.incremental.ConflictException;
import net.automatalib.words.Word;
import net.automatalib.words.WordBuilder;

/**
 * Inspired by: assist-project/dtls-fuzzer - State learner tool for DTLS which
 * uses TLS-Attacker; Copyright 2020 aSSIsT SSF project; Licensed under the MIT
 * License Source:
 * https://github.com/assist-project/dtls-fuzzer/blob/7ae686e1f86a8c45b16977c1ddd400a489402057/src/main/java/se/uu/it/dtlsfuzzer/sut/MultipleRunsSULOracle.java
 *
 * A SULOracle which executes each query multiple times in order to handle
 * non-determinism. In case the runs result in different outputs, it can perform
 * probabilistic sanitization. This entails running the query many times, and
 * computing the answer with the highest likelihood. If the likelihood is
 * greater than a threshold the answer is returned, otherwise an exception is
 * thrown.
 */
public class ProbabilisticConfidenceSULOracle<I, O> extends SULOracle<I, O> {

    private static final int MIN_EXECUTIONS = 2;
    private static final double ACCEPTABLE_PROBABILISTIC_THRESHOLD = 0.6;
    private static final double PASSABLE_PROBABILISTIC_THRESHOLD = 0.3;

    private final SUL<I, O> sul;
    private final int max_times;

    public ProbabilisticConfidenceSULOracle(SUL<I, O> sul, int max_times) {
        super(sul);
        this.sul = sul;
        this.max_times = max_times;
    }

    @Override
    public void processQueries(Collection<? extends Query<I, Word<O>>> queries) {
        queryloop:
        for (Query<I, Word<O>> q : queries) {
            LinkedHashMap<Word<O>, Integer> frequencyMap = new LinkedHashMap<>();
            for (int i = 0; i < max_times;) {
                sul.pre();
                try {
                    // Prefix: Execute symbols, don't record output
                    for (I sym : q.getPrefix()) {
                        sul.step(sym);
                    }
                    // Suffix: Execute symbols, outputs constitute output word
                    Word<I> suffix = q.getSuffix();
                    WordBuilder<O> wb = new WordBuilder<>(suffix.length());
                    for (I sym : suffix) {
                        wb.add(sul.step(sym));
                    }

                    Word<O> answer = wb.toWord();
                    frequencyMap.put(answer, frequencyMap.getOrDefault(answer, 0) + 1);
                    if (++i < MIN_EXECUTIONS) {
                        continue;
                    }
                } finally {
                    sul.post();
                }
                Entry<Word<O>, Integer> mostCommonEntry = frequencyMap.entrySet().stream().max((Entry<Word<O>, Integer> arg0, Entry<Word<O>, Integer> arg1) -> arg0.getValue().compareTo(arg1.getValue())).get();
                double likelyhood = ((double) mostCommonEntry.getValue()) / i;
                if (likelyhood >= ACCEPTABLE_PROBABILISTIC_THRESHOLD) {
                    q.answer(mostCommonEntry.getKey());
                    continue queryloop;
                } else if (likelyhood >= PASSABLE_PROBABILISTIC_THRESHOLD) {
                    continue;
                } else {
                    throw new ConflictException("Oracle does not seem to be deterministic!");
                }
            }
        }
    }
}
