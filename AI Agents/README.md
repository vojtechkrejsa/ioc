# IoCs for AI Agent Attacks

Indicators of compromise and artifacts related to attacks targeting AI agents and their configuration files.

### Table of Contents
* [OpenClaw Config Hijack](#openclaw-config-hijack)

## OpenClaw Config Hijack

Attackers modify the configuration file of the [OpenClaw](https://github.com/openclaw/openclaw) AI agent framework to enable a Telegram channel under their control. This allows the attacker to send commands to the compromised agent via Telegram direct messages.

The attack replaces the existing `openclaw.json` configuration with a modified version that:
1. Enables the Telegram channel
2. Injects the attacker's bot token
3. Sets the DM policy to `allowlist` with only the attacker's Telegram ID permitted
4. Overwrites the original config file

See [`extras/openclaw_config_hijack.ps1`](extras/openclaw_config_hijack.ps1) for the observed PowerShell command.
