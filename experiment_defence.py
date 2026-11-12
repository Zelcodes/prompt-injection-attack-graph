"""
STEP 6 - The defence experiment.

Runs the SAME end-to-end attack as before, but under three configurations:

  baseline        - no defence (re-confirms the 0.010 you already measured)
  output_filter   - the exact secret is scrubbed from the answer
  human_approval  - a reviewer refuses the secret-reading command

Each configuration runs 500 times and saves to its own file:
  results_def_baseline.csv
  results_def_output_filter.csv
  results_def_human_approval.csv

Everything else is identical to experiment.py: same attack, same varied
questions, same detectors, same save-as-you-go and resume.

WHY THESE DEFENCES ARE SIMPLE ON PURPOSE:
We want each control's effect to be predictable by the graph and checkable
exactly. The point is to demonstrate the framework's prescriptive power -
that a control on an earlier edge protects more than one on a later edge -
not to propose a new defence. Simple, deterministic controls isolate that.
"""

import os
import csv
import random

import agent
from step3_search import DocumentStore
from experiment import QUESTIONS, wilson, count_existing, report

N_RUNS = 500
SEED = 777        # a fresh seed for the defence runs

# Each configuration is just a set of switch values.
CONFIGS = {
    "baseline":       dict(OUTPUT_FILTER=False, HUMAN_APPROVAL=False),
    "output_filter":  dict(OUTPUT_FILTER=True,  HUMAN_APPROVAL=False),
    "human_approval": dict(OUTPUT_FILTER=False, HUMAN_APPROVAL=True),
}


def run_config(name, switches, store):
    path = "results_def_" + name + ".csv"
    print("\n=== CONFIG: " + name + " ===")
    print("    switches: " + str(switches))

    done = count_existing(path)
    if done >= N_RUNS:
        print("    already have " + str(done) + " runs. Skipping.")
        report(path, "canary_leaked", "leak rate (" + name + ")")
        return

    # apply this configuration's switches to the agent
    agent.OUTPUT_FILTER = switches["OUTPUT_FILTER"]
    agent.HUMAN_APPROVAL = switches["HUMAN_APPROVAL"]

    # same question sequence for every config, so they are comparable
    rng = random.Random(SEED)
    questions = [rng.choice(QUESTIONS) for _ in range(N_RUNS)]

    new_file = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["run", "question", "poison_retrieved",
                        "malicious_tool_call", "canary_leaked"])

        for i in range(done, N_RUNS):
            log = agent.run_agent(questions[i], store, verbose=False)
            w.writerow([i, questions[i],
                        int(log["poison_in_context"]),
                        int(log["malicious_tool_call"]),
                        int(log["canary_leaked"])])
            f.flush()
            if (i + 1) % 10 == 0:
                print("    run " + str(i + 1) + "/" + str(N_RUNS))

    report(path, "canary_leaked", "leak rate (" + name + ")")


if __name__ == "__main__":
    print("Loading the document store (poison included)...")
    store = DocumentStore(include_poison=True)
    print("Ready. Three configurations, 500 runs each.")
    print("Saves after every run - safe to stop and restart.\n")

    for name, switches in CONFIGS.items():
        run_config(name, switches, store)
        # reset switches to off between configs, just to be tidy
        agent.OUTPUT_FILTER = False
        agent.HUMAN_APPROVAL = False

    print("\nDONE. For each config, compare the leak rate:")
    print("  baseline        should be about 0.01 (the attack works a little)")
    print("  output_filter   should be about 0    (secret scrubbed from answer)")
    print("  human_approval  should be about 0    (secret never even read)")
    print("\nAlso look at 'malicious_tool_call' in each file:")
    print("  under human_approval the command is refused, so even the")
    print("  action is blocked - not just the leak. That is the key contrast.")
