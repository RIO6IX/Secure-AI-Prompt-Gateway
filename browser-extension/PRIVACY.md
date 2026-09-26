# Privacy Policy: Secure AI Prompt Gateway extension

_Last updated: 24 September 2026_

The Secure AI Prompt Gateway extension helps employees avoid sending
passwords, keys, card numbers and personal data to AI assistants. This
policy explains what the extension handles and where that data goes.

## What the extension reads

- **The prompt you send**, on supported AI assistant sites (ChatGPT,
  Gemini, Microsoft Copilot, Claude, Perplexity, DeepSeek, Mistral, Poe).
  It reads the prompt only when you press Enter or Send.
- **Text you paste** into the prompt box on those sites, so it can warn you
  about sensitive data before you send.
- **Your gateway login** (email and password), only when you type them into
  the extension popup.

It does not read other pages, browsing history, cookies, or anything else
on those sites.

## Where it goes

Prompt and pasted text go **only to your organisation's own Secure AI
Prompt Gateway** at the address configured in the extension. By default
that is `http://localhost:8000`. The extension never sends data to its
developers or to any third party.

On the gateway:

- A pasted-text check runs detection only. Nothing is stored.
- A prompt check writes one audit record containing the **sanitized** text
  (sensitive values replaced by placeholders), a hash of the prompt, the
  decision and the risk score. The raw prompt is not stored.

## What is stored in the browser

The extension uses `chrome.storage.local` to keep:

- your gateway session token and name, email and role, until you log out;
- a summary of the last check: decision, risk level, number of replaced
  values and time.

Prompt text is never stored by the extension.

## Permissions

- `storage`: keeps the login session and the last-check summary.
- Access to the supported AI assistant sites: lets the extension hold a
  prompt until the gateway has checked it.
- Access to `localhost:8000`: lets the extension reach your gateway.

## Contact

This extension is part of the IE3092 Information Security Project at the
Sri Lanka Institute of Information Technology (SLIIT). Questions:
contact the project team through the repository at
https://github.com/RIO6IX/Secure-AI-Prompt-Gateway.
