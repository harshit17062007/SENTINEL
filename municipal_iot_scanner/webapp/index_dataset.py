"""
index_dataset.py — one-time (or re-runnable) step that loads all 2,276
code-complexity training examples, embeds each one's *code* with Ollama's
snowflake-arctic-embed model, and stores them in a local (embedded, no
server needed) Qdrant collection.

This powers Tab 1's "closest training example" grounding panel: given new
code pasted by the user, we embed it the same way and ask Qdrant for the
nearest match(es) in this collection.

Run this once before starting the app (and again any time input.txt changes):
    python index_dataset.py

Requires Ollama running locally with the embedding model pulled:
    ollama pull snowflake-arctic-embed
"""
import re
import sys
import ollama
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

DATASET_PATH = "../data/complexity_char/input.txt"
QDRANT_PATH = "./qdrant_data"
COLLECTION_NAME = "complexity_examples"
EMBED_MODEL = "snowflake-arctic-embed"
EMBED_DIM = 1024  # snowflake-arctic-embed's output dimension


def parse_examples(path: str):
    """Split the raw training file into individual example dicts."""
    with open(path, "r") as f:
        raw = f.read()

    first_marker = raw.find("ALGORITHM COMPLEXITY TRAINING EXAMPLE #1")
    body = raw[first_marker:]
    chunks = re.split(r"(?<=END EXAMPLE\n\n)", body)
    chunks = [c.strip() for c in chunks if c.strip()]

    examples = []
    for chunk in chunks:
        lang_match = re.search(r"^Language:\s*(.+)$", chunk, re.MULTILINE)
        code_match = re.search(r"Code:\n(.*?)\n\nExpected Output:", chunk, re.DOTALL)
        time_match = re.search(r"Time Complexity:\s*(\S+)", chunk)
        space_match = re.search(r"Space Complexity:\s*(\S+)", chunk)
        reason_match = re.search(r"Reason:\n(.*?)\n\nEND EXAMPLE", chunk, re.DOTALL)

        if not (lang_match and code_match and time_match and space_match):
            continue  # skip anything that doesn't parse cleanly

        examples.append({
            "language": lang_match.group(1).strip(),
            "code": code_match.group(1).strip(),
            "time_complexity": time_match.group(1).strip(),
            "space_complexity": space_match.group(1).strip(),
            "reason": reason_match.group(1).strip() if reason_match else "",
            "full_text": chunk,
        })
    return examples


def get_embedding(text: str) -> list[float]:
    response = ollama.embeddings(model=EMBED_MODEL, prompt=text)
    return response["embedding"]


def main():
    print("Parsing dataset...")
    examples = parse_examples(DATASET_PATH)
    print(f"Parsed {len(examples)} examples")
    if not examples:
        print("ERROR: no examples parsed, check DATASET_PATH")
        sys.exit(1)

    print("Connecting to local Qdrant...")
    client = QdrantClient(path=QDRANT_PATH)

    try:
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=EMBED_DIM, distance=Distance.COSINE),
        )
        print(f"Created collection '{COLLECTION_NAME}'")
    except Exception as e:
        if "already exists" in str(e).lower():
            print(f"Collection '{COLLECTION_NAME}' already exists, will overwrite points")
        else:
            raise

    print(f"Embedding {len(examples)} examples with {EMBED_MODEL}...")
    print("(this calls Ollama once per example — may take a few minutes the first time)")

    batch = []
    BATCH_SIZE = 50
    for i, ex in enumerate(examples):
        vec = get_embedding(ex["code"])
        batch.append(PointStruct(id=i, vector=vec, payload=ex))

        if len(batch) >= BATCH_SIZE:
            client.upsert(collection_name=COLLECTION_NAME, points=batch)
            batch = []

        if (i + 1) % 100 == 0 or (i + 1) == len(examples):
            print(f"  {i + 1}/{len(examples)}")

    if batch:
        client.upsert(collection_name=COLLECTION_NAME, points=batch)

    count = client.count(collection_name=COLLECTION_NAME).count
    print(f"Done. Collection '{COLLECTION_NAME}' now has {count} points.")


if __name__ == "__main__":
    main()
