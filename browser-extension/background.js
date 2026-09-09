chrome.runtime.onInstalled.addListener(() => {
    console.log("Secure AI Prompt Gateway installed.");
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

    console.log("Received:", request);

    if (request.type === "SCAN_RESULT") {

        chrome.storage.local.set({
            lastScan: request.data
        });

    }

    sendResponse({ success: true });

    return true;

});