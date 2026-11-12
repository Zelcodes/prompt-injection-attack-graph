"""
STEP 6b - The DIRECT-attack defence experiment.

WHAT THIS FILLS IN
------------------
So far you have run:
  - the DIRECT attack with NO defence          (results_direct.csv)
  - the INDIRECT attack under three defences   (results_def_*.csv)

Missing: the DIRECT attack UNDER the defences. This script fills that gap.
It runs the direct attack (the malicious instruction is TYPED by the user)
under the same three configurations as the indirect defence run:

  baseline        - no defence
  output_filter   - the exact secret is scrubbed from the answer
  human_approval  - a reviewer refuses the secret-reading command

WHY IT MATTERS (the graph's prediction)
---------------------------------------
The direct and indirect paths differ only at the FRONT (how the text gets
in). They share the BACK half: steer -> read the secret -> reveal it.
Both defences sit on that shared back half:
  - output_filter is on the LAST edge (the answer).
  - human_approval is on the TOOL edge (the read command).
So the graph predicts BOTH defences should drive the direct leak to ~0,
exactly as they did for the indirect attack. Running this turns that
prediction into a measured fact - and completes the defence matrix.

OUTPUT (its own files, nothing else is touched)
-----------------------------------------------
  results_dirdef_baseline.csv
  results_dirdef_output_filter.csv
  results_dirdef_human_approval.csv

Same style as the other experiments: varied payload wordings, varied
questions, one shared seed so the three configs see the SAME attacks,
saved after every run, and resumable if it stops.
"""

import os
import csv
import random

import agent
from step3_search import DocumentStore
from experiment import PAYLOADS, QUESTIONS, wilson, count_existing, report

N_RUNS = 500
SEED = 333                 # fresh seed, shared by all three configs below

# Each configuration is just a set of switch values (same as the indirect run).
CONFIGS = {
    "baseline":       dict(OUTPUT_FILTER=False, HUMAN_APPROVAL=False),
    "output_filter":  dict(OUTPUT_FILTER=True,  HUMAN_APPROVAL=False),
    "human_approval": dict(OUTPUT_FILTER=False, HUMAN_APPROVAL=True),
}


def run_config(name, switches, store, combos):
    """Run all N_RUNS of the direct attack under ONE configuration."""
    path = "results_dirdef_" + name + ".csv"
    print("\n=== DIRECT + CONFIG: " + name + " ===")
    print("    switches: " + str(switches))

    # resume support: if the file already has runs, continue from there
    done = count_existing(path)
    if done >= N_RUNS:
        print("    already have " + str(done) + " runs. Skipping.")
        report(path, "canary_leaked", "direct leak rate (" + name + ")")
        return
    print("    continuing from run " + str(done) + " of " + str(N_RUNS))

    # apply this configuration's switches to the agent
    agent.OUTPUT_FILTER = switches["OUTPUT_FILTER"]
    agent.HUMAN_APPROVAL = switches["HUMAN_APPROVAL"]

    new_file = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["run", "payload_index", "question",
                        "malicious_tool_call", "canary_leaked"])

        for i in range(done, N_RUNS):
            payload, question = combos[i]
            # DIRECT injection: the malicious text is placed in the USER's
            # message (extra_injection), and the store is CLEAN (no poison).
            log = agent.run_agent(question, store,
                                  extra_injection=payload, verbose=False)
            w.writerow([i, PAYLOADS.index(payload), question,
                        int(log["malicious_tool_call"]),
                        int(log["canary_leaked"])])
            f.flush()
            if (i + 1) % 10 == 0:
                print("    run " + str(i + 1) + "/" + str(N_RUNS))

    report(path, "canary_leaked", "direct leak rate (" + name + ")")
    report(path, "malicious_tool_call",
           "direct: agent obeyed and read the secret (" + name + ")")


if __name__ == "__main__":
    print("Loading the document store (CLEAN - direct attack needs no poison)...")
    # Direct injection does not use a retrieved document, so the store is clean.
    store = DocumentStore(include_poison=False)

    # Build the attack sequence ONCE, so all three configs face identical
    # (payload, question) pairs. This is what makes the comparison fair.
    rng = random.Random(SEED)
    combos = [(rng.choice(PAYLOADS), rng.choice(QUESTIONS))
              for _ in range(N_RUNS)]

    print("Ready. Three configurations, 500 runs each, same attacks.")
    print("Saves after every run - safe to stop and restart.\n")

    for name, switches in CONFIGS.items():
        run_config(name, switches, store, combos)
        # reset switches to off between configs, just to be tidy
        agent.OUTPUT_FILTER = False
        agent.HUMAN_APPROVAL = False

    print("\nDONE. Results saved to the three results_dirdef_*.csv files.")
    print("The graph predicts:")
    print("  baseline        ~ 0.03  (direct attack works a little; higher than indirect)")
    print("  output_filter   ~ 0     (secret scrubbed from the answer)")
    print("  human_approval  ~ 0     (secret never even read)")
    print("If output_filter and human_approval both hit ~0 on the DIRECT attack too,")
    print("that confirms: a control on a shared choke point protects EVERY path")
    print("through it - both entry surfaces, not just the indirect one.")
