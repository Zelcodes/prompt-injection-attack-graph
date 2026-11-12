"""
STEP 5b - The DIRECT injection experiment.

Experiments A and B measured INDIRECT injection: the attack was hidden in
a document the system retrieved. This one measures DIRECT injection: the
USER types the malicious instruction straight into the chat.

Why this matters for the graph:
  The direct path is SHORTER. There is no document and no search, so the
  retrieval edge does not exist. The chain is just:
        injection  ->  exfiltration
  The graph predicts a shorter path is MORE likely to succeed. Measuring
  this lets us show that, with real numbers, next to the indirect result.

It writes to its OWN file:
        results_direct.csv
so it does not touch results_injection.csv or results_endtoend.csv.
Safe to run in the same folder as experiments A and B.

Same style as before: varied wordings, varied questions, save-as-you-go,
resumable. Set N_RUNS below (500, to match A and B).
"""

import os
import csv
import random

import agent
from step3_search import DocumentStore
from experiment import PAYLOADS, QUESTIONS, wilson, count_existing, report

N_RUNS = 500
SEED = 2024               # a fresh seed, separate from A and B
DIRECT_CSV = "results_direct.csv"


def measure_direct(store):
    print("=== DIRECT injection (user types the malicious instruction) ===")
    done = count_existing(DIRECT_CSV)
    if done >= N_RUNS:
        print("Already have " + str(done) + " runs. Skipping.")
        report(DIRECT_CSV, "canary_leaked", "direct leak rate")
        return
    print("Continuing from run " + str(done) + " of " + str(N_RUNS))

    rng = random.Random(SEED)
    combos = [(rng.choice(PAYLOADS), rng.choice(QUESTIONS))
              for _ in range(N_RUNS)]

    new_file = not os.path.exists(DIRECT_CSV)
    with open(DIRECT_CSV, "a", newline="") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["run", "payload_index", "question",
                        "malicious_tool_call", "canary_leaked"])

        for i in range(done, N_RUNS):
            payload, question = combos[i]
            # DIRECT: the malicious text is placed in the USER's message
            # (via extra_injection), not in a retrieved document.
            log = agent.run_agent(question, store,
                                  extra_injection=payload, verbose=False)
            w.writerow([i, PAYLOADS.index(payload), question,
                        int(log["malicious_tool_call"]),
                        int(log["canary_leaked"])])
            f.flush()
            if (i + 1) % 10 == 0:
                print("  run " + str(i + 1) + "/" + str(N_RUNS))

    report(DIRECT_CSV, "canary_leaked",
           "direct-injection leak rate (whole short attack)")
    report(DIRECT_CSV, "malicious_tool_call",
           "direct-injection: agent obeyed and read the secret")


if __name__ == "__main__":
    print("Loading the document store (poison NOT needed for direct)...")
    # Direct injection does not rely on a retrieved poison document, so we
    # use a CLEAN store. The only injection is the one the user types.
    store = DocumentStore(include_poison=False)
    print("Ready. Running direct injection, saving to " + DIRECT_CSV + "\n")
    measure_direct(store)
    print("\nDONE. Results saved to results_direct.csv.")
    print("Compare its leak rate to the end-to-end (indirect) rate:")
    print("  the direct path is shorter, so the graph predicts it should")
    print("  succeed MORE often than the indirect one.")
