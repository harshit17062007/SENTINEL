"""
retrieval.py — given a piece of code, find the most similar example(s) in
our indexed training set (see index_dataset.py). This is the "closest
training example" grounding panel in Tab 1, and it's genuine nearest-
neighbor retrieval — not the model's opinion of similarity.

Requires Ollama running locally with snowflake-arctic-embed pulled, and
index_dataset.py already run at least once (creates ./qdrant_data).
"""
import ollama
from qdrant_client import QdrantClient

QDRANT_PATH = "./qdrant_data"
COLLECTION_NAME = "complexity_examples"
EMBED_MODEL = "snowflake-arctic-embed"

_client = None


def get_client() -> QdrantClient:
    global _client
    if _client is None:
        _client = QdrantClient(path=QDRANT_PATH)
    return _client


def embed(text: str) -> list[float]:
    response = ollama.embeddings(model=EMBED_MODEL, prompt=text)
    return response["embedding"]


def find_closest_example(code: str, top_k: int = 1) -> list[dict]:
    """
    Returns up to top_k closest training examples, each as:
        {"score": float 0-1, "language": str, "code": str,
         "time_complexity": str, "space_complexity": str,
         "reason": str, "full_text": str}
    score is cosine similarity — genuine, not the model's guess.
    """
    client = get_client()
    query_vec = embed(code)
    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vec,
        limit=top_k,
    )
    out = []
    for r in results.points:
        payload = dict(r.payload)
        payload["score"] = r.score
        out.append(payload)
    return out


def collection_ready() -> bool:
    """Check whether index_dataset.py has been run (collection exists and has points)."""
    try:
        client = get_client()
        info = client.count(collection_name=COLLECTION_NAME)
        return info.count > 0
    except Exception:
        return False
