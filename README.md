# CyberOrion

CyberOrion is an autonomous cybersecurity research and operations platform built
around the CAI framework. It combines CTF execution, attack-chain
reconstruction, code-vulnerability repair, security knowledge retrieval,
multi-agent orchestration, telemetry, evaluation, and a browser terminal.

## Repository layout

- `cyberorion/` — CyberOrion application, backend, frontend, scenarios, tools,
  tests, and deployment documentation.
- `cai-latest/` — the CAI framework source with CyberOrion-specific agent
  integrations.
- `benchmarks/` — benchmark harnesses and curated source code. Large downloaded
  datasets are intentionally excluded.
- Root scripts and documents — diagnostics, research notes, and reproducibility
  material retained from the development workspace.

## Quick start

1. Create a Python 3.10+ environment outside this repository.
2. Copy `cyberorion/.env.example` to a local `.env` file outside version
   control and configure the model endpoint.
3. Install the CAI and CyberOrion dependencies described in
   `cyberorion/README.md`.
4. Run the focused test suite:

   ```bash
   cai_env/bin/python -m pytest cyberorion/tests/ -q
   ```

5. Build the frontend:

   ```bash
   cd cyberorion/web
   npm install
   npm run build
   ```

See `cyberorion/AGENTS.md` and `cyberorion/docs/` for architecture, security
boundaries, deployment, and reproducibility details.

## Security

Never commit API keys, SSH keys, production credentials, virtual environments,
runtime logs, or downloaded benchmark datasets. Use local environment variables
or a secret manager for credentials.
