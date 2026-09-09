console.log("Secure AI Prompt Gateway Loaded");

let updatingEditor = false;

function attachListener() {

    const editor = document.querySelector('[contenteditable="true"]');

    if (!editor)
        return;

    if (editor.dataset.gatewayAttached)
        return;

    editor.dataset.gatewayAttached = "true";

    console.log("ChatGPT editor found.");

    const sendButton = document.querySelector('button[data-testid="send-button"]');

if (sendButton) {
    console.log("Send button found.");
}

    editor.addEventListener("input", async () => {

        //console.log("updatingEditor =", updatingEditor);

        if (updatingEditor)
        return;

        const prompt = editor.innerText.trim();

        if (!prompt)
            return;

        const storage = await chrome.storage.local.get(["jwt", "user"]);

        if (!storage.jwt)
            return;

        try {

            const response = await fetch("http://localhost:8000/inspect", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + storage.jwt
                },
                body: JSON.stringify({
                    actor: storage.user.email,
                    department: "IT",
                    service: "ChatGPT",
                    prompt: prompt,
                    source: "browser-extension"
                })
            });

            const result = await response.json();

            console.log("========== INSPECTION ==========");
            console.log("Risk:", result.risk);
            console.log("Score:", result.riskScore);
            console.log("Status:", result.status);
            console.log("Action:", result.action);
            console.log("Sanitized Prompt:");
            console.log(result.maskedOutput);
            console.log(result);

            if (
    result.status === "Sanitized" &&
    result.maskedOutput &&
    result.maskedOutput !== prompt
) {

    updatingEditor = true;

    editor.focus();

    document.execCommand("selectAll", false, null);
    document.execCommand("insertText", false, result.maskedOutput);

    setTimeout(() => {
        updatingEditor = false;
    }, 100);

    console.log("Prompt automatically sanitized.");
}

        } catch (err) {

            console.error(err);

        }

    });

}

const observer = new MutationObserver(() => {

    attachListener();

});

observer.observe(document.body, {

    childList: true,

    subtree: true

});

attachListener();