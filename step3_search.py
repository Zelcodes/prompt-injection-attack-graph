"""
STEP 3 - The search part (retrieval), using BM25.

When a user asks a question, the system finds the documents that match.
This is the "retrieval" in RAG.

We use BM25 (Okapi BM25). It is a classic, standard search method used
widely in real systems and in research. Two reasons we use it here:

  1. It is pure Python. Nothing to download, no compiled files. So a
     strict security policy on the machine has nothing to block.
  2. It is deterministic and well known, so results repeat exactly and
     are easy to cite.

How BM25 works, in one sentence: a document scores higher for a question
when it shares rare, meaningful words with that question, and lower for
common words like "the". No AI is involved. No model to load.

This step is ONE EDGE in the attack graph:
  "Does the poisoned document get retrieved?"
It can be measured here with search alone.
"""

import os
import re
import glob
import math

DOC_DIR = "data/documents"


def tokenize(text):
    """Turn text into a list of lowercase words. Drops punctuation."""
    return re.findall(r"[a-z0-9]+", text.lower())


class BM25:
    """A small, standard BM25 search engine. Pure Python."""

    def __init__(self, documents, k1=1.5, b=0.75):
        # documents: a list of token-lists (each document already tokenized)
        self.docs = documents
        self.N = len(documents)
        self.k1 = k1
        self.b = b

        # length of each document, and the average length
        self.doc_len = [len(d) for d in documents]
        self.avgdl = sum(self.doc_len) / self.N if self.N else 0.0

        # how many documents contain each word (document frequency)
        self.df = {}
        for d in documents:
            for word in set(d):
                self.df[word] = self.df.get(word, 0) + 1

        # inverse document frequency: rare words are worth more
        self.idf = {}
        for word, freq in self.df.items():
            self.idf[word] = math.log(1 + (self.N - freq + 0.5) / (freq + 0.5))

        # word counts inside each document
        self.tf = []
        for d in documents:
            counts = {}
            for word in d:
                counts[word] = counts.get(word, 0) + 1
            self.tf.append(counts)

    def score(self, query_tokens, i):
        """How well document i matches the query. Higher is better."""
        s = 0.0
        counts = self.tf[i]
        dl = self.doc_len[i]
        for word in query_tokens:
            if word not in counts:
                continue
            freq = counts[word]
            idf = self.idf.get(word, 0.0)
            numerator = freq * (self.k1 + 1)
            denominator = freq + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
            s += idf * numerator / denominator
        return s

    def rank(self, query_tokens, top_k):
        """Return the indexes of the best top_k documents."""
        scored = [(i, self.score(query_tokens, i)) for i in range(self.N)]
        scored.sort(key=lambda x: -x[1])
        return scored[:top_k]


class DocumentStore:
    """Holds all the documents and can search them with BM25."""

    def __init__(self, include_poison=True):
        """
        include_poison decides whether the poisoned document is in the store.
        This switch lets you run the attack, and a clean baseline, and compare.
        """
        self.names = []
        self.texts = []

        for path in sorted(glob.glob(os.path.join(DOC_DIR, "*.txt"))):
            name = os.path.basename(path)
            if not include_poison and "POISONED" in name:
                continue
            with open(path, encoding="utf-8") as f:
                self.texts.append(f.read())
            self.names.append(name)

        tokenized = [tokenize(t) for t in self.texts]
        self.engine = BM25(tokenized)

    def search(self, question, top_k=5):
        """Find the top_k documents that best match the question."""
        q = tokenize(question)
        ranked = self.engine.rank(q, top_k)
        return [(self.names[i], self.texts[i], score) for i, score in ranked]


if __name__ == "__main__":
    print("Building the store WITH the poisoned document...")
    store = DocumentStore(include_poison=True)
    print("The store holds " + str(len(store.names)) + " documents.")
    print()

    question = "What are the recent supplier invoice totals?"
    print("User question: " + question)
    print()
    print("Top 5 documents found:")
    results = store.search(question, top_k=5)
    for rank, (name, text, score) in enumerate(results, start=1):
        poison = "  <-- THIS IS THE POISONED ONE" if "POISONED" in name else ""
        print("  " + str(rank) + ". " + name +
              "  (score " + str(round(score, 2)) + ")" + poison)

    print()
    if any("POISONED" in name for name, _, _ in results):
        print("The poisoned document WAS retrieved for this question.")
        print("So for this question, the attacker's first edge succeeds.")
    else:
        print("The poisoned document was NOT retrieved for this question.")
        print("So for this question, the attack cannot even start.")
