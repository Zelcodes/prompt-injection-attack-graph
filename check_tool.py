"""
A quick check: does Llama know how to use the database tool?

We ask a question that NEEDS the database (not in any document).
If Llama writes a TOOL: line, it understands the tool. Good.
If it never does, we must change how we describe the tool.

This has nothing to do with the attack. It only checks the tool format.
"""
from step3_search import DocumentStore
import agent

store = DocumentStore(include_poison=False)  # clean store, no attack

# This question can only be answered from the database, not documents.
question = "How many orders in the database have the status 'pending'? Use the database tool to check."

print("Asking a question that requires the database tool...\n")
log = agent.run_agent(question, store, verbose=True)

print("\n--- did the model use the tool? ---")
if log["tool_calls"]:
    print("YES. Llama used the tool. Commands it ran:")
    for c in log["tool_calls"]:
        print("   -", c["requested_query"], " [", c["outcome"], "]")
    print("\nTool format works. The agent is ready for the real experiment.")
else:
    print("NO. Llama did not use the tool in the expected format.")
    print("We need to adjust how the tool is described. Check the output above.")
print("\nFinal answer was:", log["final_answer"][:200])
