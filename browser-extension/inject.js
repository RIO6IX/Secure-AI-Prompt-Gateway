(() => {

    const token = localStorage.getItem("secure_ai_gateway_token");

    window.postMessage({
        type: "SECURE_AI_GATEWAY_TOKEN",
        token: token
    }, "*");

})();