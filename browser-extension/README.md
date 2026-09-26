# Secure AI Prompt Gateway: Browser Extension

Chrome/Edge (Manifest V3) extension that checks prompts on ChatGPT, Gemini,
Copilot (consumer and Microsoft 365), Claude, Perplexity, DeepSeek, Mistral
Le Chat and Poe with the local gateway **before** they are sent.

## How it works

1. The content script holds the submission when you press Enter or click
   Send.
2. The prompt goes to the background service worker, which calls
   `POST /api/v1/sanitize` on the gateway with your login token. The call runs
   in the service worker because the AI site's origin would otherwise be
   blocked by CORS.
3. The gateway runs detection, sanitization, risk scoring and policy, and
   writes one audit record.
4. The extension then acts on the decision:
   - **ALLOW**: the prompt is sent unchanged.
   - **SANITIZE**: the text is replaced with the placeholder version (for
     example `[EMAIL_ADDRESS_1]`). Review it and press Send again.
   - **BLOCK**: nothing is sent, and a notice explains why.

If the gateway is offline or you are not logged in, the prompt is held
(fail closed). The extension stores only your token and a summary of the
last check. It never stores prompt text.

## Install (developer mode)

1. Start the backend: `cd Dashboard/python_gateway` then
   `python -m uvicorn app:app --host 127.0.0.1 --port 8000`.
2. Open `chrome://extensions`, enable **Developer mode**, click **Load
   unpacked** and select this `browser-extension` folder.
3. Click the extension icon and log in with a gateway `admin` or `user`
   account. Auditor accounts are read-only and cannot submit prompts.
4. Paste a test prompt into the popup's **Test a Prompt** box, or type on a
   supported AI site.

## Tests

The service worker is tested against a mock gateway. The tests need
Node.js 22 and no npm packages:

```
cd browser-extension
npm test        # login, ALLOW/SANITIZE/BLOCK, badges, 429, outages, expired session
npm run check   # syntax check of all extension scripts
```

The toolbar badge shows `!` on the tab where values were replaced and
`X` where a prompt was blocked.

## Paste warnings

Pasting sensitive text into a supported site shows a warning right away,
listing what was found and saying it will be replaced or blocked on send.
The check uses detection only (`/api/v1/detect`), so pastes create no
audit records. The real, audited check still happens when you send.

## Publishing (Chrome Web Store / Edge Add-ons)

```
npm run icons     # regenerate icons/ (Pillow)
npm run package   # dist/secure-ai-prompt-gateway-<version>.zip
```

The package contains only runtime files. It fails if `manifest.json`
references a file that doesn't exist. Upload the zip together with the
privacy policy in [PRIVACY.md](PRIVACY.md); the Store requires one for
extensions that handle user data.
