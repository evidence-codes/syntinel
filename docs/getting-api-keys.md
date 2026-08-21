# Getting an API key

Syntinel's LLM engine calls [Groq](https://console.groq.com) for fast,
cheap inference against Qwen 2.5 Coder.

1. Create a free account at https://console.groq.com
2. Generate an API key under **API Keys**
3. `export GROQ_API_KEY=...` or add it to a `.env` file at your repo root
   (see `.env.example`)

Without a key, `syntinel scan` still runs the Semgrep engine — pass
`--no-llm` explicitly to skip the warning about the missing key.
