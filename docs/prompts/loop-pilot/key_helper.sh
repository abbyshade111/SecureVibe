#!/bin/sh
# apiKeyHelper for the loop trials (loop_trial.py --api): prints the Anthropic key from the .env file named by
# SV_KEY_ENV_FILE, for the Claude program only. The key is never put in any program's environment.
sed -n 's/^ANTHROPIC_API_KEY=//p' "${SV_KEY_ENV_FILE:?name the .env file that holds the key}" | head -1 | tr -d "\"'"
