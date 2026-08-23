"""
app.py — the actual web UI.

Tab 1: our trained complexity model, grounded by showing it the closest
       training example before asking about new code (few-shot grounding,
       not instruction-following RAG — see project notes on why).
Tab 2: general PDF/web assistant, following the deepseek_local_rag_agent
       pattern but with local (embedded) Qdrant instead of Qdrant Cloud.
       Requires Ollama running locally with a chat model pulled
       (e.g. deepseek-r1:1.5b or llama3.2).

Run with: streamlit run app.py
"""
import os
import tempfile
from datetime import datetime

import streamlit as st
import bs4
from langchain_community.document_loaders import PyPDFLoader, WebBaseLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_qdrant import QdrantVectorStore
from langchain_core.embeddings import Embeddings
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams
from agno.agent import Agent
from agno.models.ollama import Ollama

import retrieval
from complexity_model import analyze_code

# ---------------------------------------------------------------------------
# Shared config
# ---------------------------------------------------------------------------
QDRANT_PATH = "./qdrant_data"
DOCS_COLLECTION = "user_documents"
EMBED_MODEL = "snowflake-arctic-embed"
EMBED_DIM = 1024

st.set_page_config(page_title="Code Complexity + Doc Assistant", layout="wide")


class OllamaLangchainEmbedder(Embeddings):
    """Adapts Ollama's embedding call to LangChain's Embeddings interface,
    so langchain_qdrant can use it directly."""

    def __init__(self, model_name=EMBED_MODEL):
        self.model_name = model_name

    def embed_documents(self, texts):
        return [self.embed_query(t) for t in texts]

    def embed_query(self, text):
        return retrieval.embed(text)


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
for key, default in [
    ("doc_history", []),
    ("processed_documents", []),
    ("doc_vector_store", None),
    ("chat_model", "deepseek-r1:1.5b"),
    ("use_web_search", False),
    ("exa_api_key", ""),
    ("similarity_threshold", 0.5),
]:
    if key not in st.session_state:
        st.session_state[key] = default


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab1, tab2 = st.tabs(["Code Complexity Analyzer", "Document & Web Assistant"])

# ============================= TAB 1 ========================================
with tab1:
    st.header("Code Complexity Analyzer")
    st.caption(
        "Our own trained model, grounded on the closest matching example from "
        "its training set — not general document Q&A."
    )

    col_lang, _ = st.columns([1, 3])
    with col_lang:
        language = st.selectbox("Language", ["Python", "C++", "Java"])

    code_input = st.text_area(
        "Paste code",
        height=180,
        placeholder="def foo(n):\n    for i in range(n):\n        print(i)",
    )

    if st.button("Analyze", type="primary"):
        if not code_input.strip():
            st.warning("Paste some code first.")
        else:
            with st.spinner("Finding closest training example..."):
                try:
                    matches = retrieval.find_closest_example(code_input, top_k=1)
                    closest = matches[0] if matches else None
                except Exception as e:
                    closest = None
                    st.warning(
                        f"Retrieval unavailable ({e}). Falling back to zero-shot "
                        "(model will answer without a grounding example — likely "
                        "lower quality)."
                    )

            with st.spinner("Running our model..."):
                result = analyze_code(code_input, language, few_shot_example=closest)

            col_answer, col_grounding = st.columns(2)

            with col_answer:
                st.subheader("Model's answer")
                if result["time_complexity"]:
                    st.markdown(
                        f"**Time:** `{result['time_complexity']}`  "
                        f"**Space:** `{result['space_complexity']}`"
                    )
                    st.write(result["reason"] or "_(no reason text generated)_")
                else:
                    st.error(
                        "Model didn't produce a parseable answer. Raw output:"
                    )
                    st.code(result["raw_cropped"])

            with col_grounding:
                st.subheader("Closest training example")
                if closest:
                    pct = round(closest["score"] * 100)
                    badge = "🟢" if pct >= 80 else ("🟡" if pct >= 50 else "🔴")
                    st.markdown(f"{badge} **{pct}% match**")
                    st.code(closest["code"], language=closest["language"].lower())
                    st.caption(
                        f"Labeled: {closest['time_complexity']} time, "
                        f"{closest['space_complexity']} space"
                    )
                else:
                    st.info(
                        "No retrieval index found yet. Run `python index_dataset.py` "
                        "first (requires Ollama + snowflake-arctic-embed)."
                    )

            with st.expander("Show raw model output (debug)"):
                st.code(result["raw_cropped"])

# ============================= TAB 2 ========================================
with tab2:
    st.header("Document & Web Assistant")
    st.caption(
        "General-purpose chat over your own PDFs/URLs, powered by a real local "
        "LLM via Ollama — separate from our trained model above."
    )

    with st.sidebar:
        st.header("Document Assistant Settings")
        st.session_state.chat_model = st.radio(
            "Chat model", options=["deepseek-r1:1.5b", "deepseek-r1:7b", "llama3.2"]
        )
        st.session_state.similarity_threshold = st.slider(
            "Document similarity threshold", 0.0, 1.0, st.session_state.similarity_threshold
        )
        st.session_state.use_web_search = st.checkbox(
            "Enable web search fallback (needs Exa API key)",
            value=st.session_state.use_web_search,
        )
        if st.session_state.use_web_search:
            st.session_state.exa_api_key = st.text_input(
                "Exa API key", type="password", value=st.session_state.exa_api_key
            )

        st.divider()
        st.header("Upload documents")
        uploaded_file = st.file_uploader("Upload PDF", type=["pdf"])
        web_url = st.text_input("Or enter a URL")

        if st.session_state.processed_documents:
            st.subheader("Indexed sources")
            for src in st.session_state.processed_documents:
                st.text(("📄 " if src.endswith(".pdf") else "🌐 ") + src)

    def init_doc_qdrant() -> QdrantClient:
        return QdrantClient(path=QDRANT_PATH)

    def process_pdf(file):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(file.getvalue())
            loader = PyPDFLoader(tmp.name)
            documents = loader.load()
        for doc in documents:
            doc.metadata.update({
                "source_type": "pdf", "file_name": file.name,
                "timestamp": datetime.now().isoformat(),
            })
        splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
        return splitter.split_documents(documents)

    def process_web(url):
        loader = WebBaseLoader(
            web_paths=(url,),
            bs_kwargs=dict(parse_only=bs4.SoupStrainer(
                class_=("post-content", "post-title", "post-header", "content", "main")
            )),
        )
        documents = loader.load()
        for doc in documents:
            doc.metadata.update({
                "source_type": "url", "url": url,
                "timestamp": datetime.now().isoformat(),
            })
        splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
        return splitter.split_documents(documents)

    def get_or_create_doc_store(client):
        try:
            client.create_collection(
                collection_name=DOCS_COLLECTION,
                vectors_config=VectorParams(size=EMBED_DIM, distance=Distance.COSINE),
            )
        except Exception as e:
            if "already exists" not in str(e).lower():
                raise
        return QdrantVectorStore(
            client=client, collection_name=DOCS_COLLECTION,
            embedding=OllamaLangchainEmbedder(),
        )

    def get_chat_agent():
        return Agent(
            name="Document Assistant",
            model=Ollama(id=st.session_state.chat_model),
            instructions="""You answer questions using the provided context when
given. Be precise and cite specific details from the context. If no context
is given, answer from what you know and say so.""",
            markdown=True,
        )

    def get_web_search_agent():
        from agno.tools.exa import ExaTools
        return Agent(
            name="Web Search Agent",
            model=Ollama(id="llama3.2"),
            tools=[ExaTools(api_key=st.session_state.exa_api_key, num_results=5)],
            instructions="Search the web, compile relevant info, include sources.",
            markdown=True,
        )

    # ingest new uploads
    doc_client = init_doc_qdrant()
    if uploaded_file and uploaded_file.name not in st.session_state.processed_documents:
        with st.spinner("Processing PDF..."):
            texts = process_pdf(uploaded_file)
            if texts:
                if st.session_state.doc_vector_store is None:
                    st.session_state.doc_vector_store = get_or_create_doc_store(doc_client)
                st.session_state.doc_vector_store.add_documents(texts)
                st.session_state.processed_documents.append(uploaded_file.name)
                st.success(f"Indexed: {uploaded_file.name}")

    if web_url and web_url not in st.session_state.processed_documents:
        with st.spinner("Processing URL..."):
            texts = process_web(web_url)
            if texts:
                if st.session_state.doc_vector_store is None:
                    st.session_state.doc_vector_store = get_or_create_doc_store(doc_client)
                st.session_state.doc_vector_store.add_documents(texts)
                st.session_state.processed_documents.append(web_url)
                st.success(f"Indexed: {web_url}")

    # chat history
    for msg in st.session_state.doc_history:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])

    prompt = st.chat_input("Ask about your documents, or ask anything...")
    if prompt:
        st.session_state.doc_history.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)

        context, docs = "", []
        if st.session_state.doc_vector_store:
            retriever = st.session_state.doc_vector_store.as_retriever(
                search_type="similarity_score_threshold",
                search_kwargs={"k": 5, "score_threshold": st.session_state.similarity_threshold},
            )
            docs = retriever.invoke(prompt)
            if docs:
                context = "\n\n".join(d.page_content for d in docs)
                st.info(f"Found {len(docs)} relevant chunk(s) in your documents.")

        if not context and st.session_state.use_web_search and not st.session_state.exa_api_key:
            st.warning(
                "Web search is enabled but no Exa API key is set — skipping web search "
                "and answering from general knowledge instead. Add a key in the sidebar "
                "to use this fallback."
            )

        if not context and st.session_state.use_web_search and st.session_state.exa_api_key:
            with st.spinner("Searching the web..."):
                try:
                    web_agent = get_web_search_agent()
                    web_results = web_agent.run(prompt).content
                    if web_results:
                        context = f"Web Search Results:\n{web_results}"
                        st.info("No matching document content — used web search instead.")
                except Exception as e:
                    st.error(f"Web search error: {e}")

        with st.spinner("Thinking..."):
            try:
                agent = get_chat_agent()
                full_prompt = (
                    f"Context: {context}\n\nQuestion: {prompt}\n\nAnswer based on the context."
                    if context else prompt
                )
                response = agent.run(full_prompt)
                answer = response.content
            except Exception as e:
                answer = f"Error: {e} (is Ollama running with `{st.session_state.chat_model}` pulled?)"

        st.session_state.doc_history.append({"role": "assistant", "content": answer})
        with st.chat_message("assistant"):
            st.write(answer)
            if docs:
                with st.expander("Sources"):
                    for i, d in enumerate(docs, 1):
                        st.write(f"**Source {i}:** {d.page_content[:200]}...")
