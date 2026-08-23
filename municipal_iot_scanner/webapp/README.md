# Code Complexity + Document Assistant — Web App

Two-tab local web app:
- **Tab 1:** our own trained complexity model, grounded with the closest
  matching example from its training set (real similarity search, not the
  model's opinion).
- **Tab 2:** general PDF/URL chat + optional web search, powered by a real
  small LLM running locally via Ollama.

Everything runs on your machine. No cloud accounts required except
(optionally) a free Exa API key if you want the web search fallback.

## 1. Install Ollama

Download and install from https://ollama.com/download (Windows installer).
After installing, open a **new** PowerShell window and confirm it works:
```
ollama --version
```

## 2. Pull the models

```
ollama pull snowflake-arctic-embed
ollama pull deepseek-r1:1.5b
```
(`snowflake-arctic-embed` powers the retrieval/grounding in both tabs.
`deepseek-r1:1.5b` is the chat model for Tab 2 — swap for `llama3.2` or
`deepseek-r1:7b` in the app's sidebar if you want to try alternatives; your
3050 can likely handle 7b too, just slower.)

Ollama runs as a background service after install, so these models are
available to any app on your machine going forward — you don't need to
manually start a server.

## 3. Install Python dependencies

From inside this `webapp` folder:
```
python -m pip install -r requirements.txt
```
(If you already installed the CUDA build of torch for the training project,
that's fine — this will detect it's already there and skip reinstalling,
or you can remove `torch` from requirements.txt if you want to be safe
about not overwriting your CUDA install.)

## 4. Index the training dataset (Tab 1's grounding data)

This embeds all 2,276 training examples and stores them in a local vector
database (`./qdrant_data`, created automatically — no server, no signup).
Only needs to be run once (or again if you change the dataset):
```
python index_dataset.py
```
This calls Ollama once per example, so it'll take a few minutes the first
time. You'll see progress printed every 100 examples.

## 5. Run the app

```
streamlit run app.py
```
This opens automatically in your browser at `http://localhost:8501`.

## Notes on what's genuinely different between the two tabs

- **Tab 1** does NOT use the general chat LLM at all — it only uses our own
  trained GPT (from `../out-complexity-char/ckpt.pt`). The retrieval step
  finds the closest training example and shows it to our model as a worked
  example right before asking about your new code — this is "few-shot
  grounding," which is what a model like ours (not instruction-tuned) can
  actually make use of.
- **Tab 2** uses a real general-purpose LLM that can read and reason about
  arbitrary text — this is the part that can actually do open-ended
  document Q&A the way the original DeepSeek RAG repo does.
- Both tabs share the same local Qdrant database file but use **separate
  collections** (`complexity_examples` for Tab 1, `user_documents` for
  Tab 2) so they don't interfere with each other.

## Troubleshooting

- **"Connection refused" / embedding or chat errors:** Ollama isn't
  running. It should auto-start after install; if not, run `ollama serve`
  in a separate terminal window and leave it open.
- **Tab 1 says "No retrieval index found yet":** you haven't run
  `python index_dataset.py` yet, or it errored partway through — rerun it
  and check for errors in the terminal output.
- **Web search checkbox does nothing:** you need a free Exa API key from
  https://exa.ai — paste it into the sidebar field once you have one.
