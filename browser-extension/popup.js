const backendStatus = document.getElementById("backendStatus");
const userStatus = document.getElementById("userStatus");

const promptInput = document.getElementById("promptInput");

const riskLevel = document.getElementById("riskLevel");

const riskScore = document.getElementById("riskScore");

const statusText = document.getElementById("status");

const actionText = document.getElementById("action");

const categoryText = document.getElementById("category");

const findingText = document.getElementById("finding");

const sanitizedOutput = document.getElementById("sanitizedOutput");

async function checkBackend() {

    try {

        const response = await fetch("http://localhost:8000/health");

        if (response.ok) {

            backendStatus.innerHTML =
                '<span class="status-dot"></span>Connected';

        } else {

            backendStatus.innerHTML =
                '<span class="status-dot offline-dot"></span>Backend Error';

        }

    } catch (error) {

        backendStatus.innerHTML =
            '<span class="status-dot offline-dot"></span>Offline';

    }

}

async function login() {

    const email = document.getElementById("email").value.trim();

    const password = document.getElementById("password").value;

    if (!email || !password) {

        alert("Please enter email and password.");

        return;

    }

    try {

        const response = await fetch("http://localhost:8000/auth/login", {

            method: "POST",

            headers: {

                "Content-Type": "application/json"

            },

            body: JSON.stringify({

                email,

                password

            })

        });

        const data = await response.json();

        console.log(data);

        if (!response.ok) {

            alert(data.detail || "Login failed");

            return;

        }

        chrome.storage.local.set({

            jwt: data.token,

            user: data.user

        });

        loginCard.style.display = "none";

        console.log("Logged in user:", data.user);

        userStatus.innerHTML =
            `<b>${data.user.name}</b><br>${data.user.email}`;

        alert("Login Successful");

    } catch (error) {

        console.error(error);

        alert("Cannot connect to backend.");

    }

}

async function inspectPrompt() {

    const prompt = promptInput.value.trim();

    if (!prompt) {
        alert("Please enter a prompt.");
        return;
    }

    chrome.storage.local.get(["jwt", "user"], async (result) => {

        if (!result.jwt) {
            alert("Please login first.");
            return;
        }

        try {

            const response = await fetch("http://localhost:8000/inspect", {

                method: "POST",

                headers: {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + result.jwt
                },

                body: JSON.stringify({

                    actor: result.user.email,

                    department: "IT",

                    service: "ChatGPT",

                    prompt: prompt,

                    source: "browser-extension"

                })

            });

            const data = await response.json();

            console.log(data);

            if (!response.ok) {

                alert(data.detail || "Inspection failed");

                return;

            }

            riskLevel.innerText = data.risk.toUpperCase();

            riskScore.innerText = data.riskScore + " / 100";

            statusText.innerText = data.status;

            actionText.innerText = data.action;

            categoryText.innerHTML =
                `<span class="info-badge">${data.category || "-"}</span>`;

            findingText.innerHTML =
                `<span class="info-badge">${data.finding || "-"}</span>`;

            const scoreBar = document.getElementById("scoreBar");

            scoreBar.style.width = data.riskScore + "%";

            riskLevel.className = "risk-badge";

            if (data.risk === "High") {

                riskLevel.style.background = "#d92d20";
                scoreBar.style.background = "#d92d20";

            }
            else if (data.risk === "Medium") {

                riskLevel.style.background = "#f5a524";
                scoreBar.style.background = "#f5a524";

            }
            else {

                riskLevel.style.background = "#16a34a";
                scoreBar.style.background = "#16a34a";

            }

            sanitizedOutput.value =
                data.maskedOutput || "";

        } catch (err) {

            console.error(err);

            alert("Cannot connect to backend.");

        }

    });

}

const loginCard = document.getElementById("loginCard");

const logoutButton = document.getElementById("logoutButton");

chrome.storage.local.get(["jwt", "user"], (result) => {

    if (result.user) {

        userStatus.innerHTML =
            `<strong>${result.user.name}</strong><br>${result.user.email}`;

        loginCard.style.display = "none";
        logoutButton.style.display = "inline-block";

    } else {

        loginCard.style.display = "block";
        logoutButton.style.display = "none";

        userStatus.innerHTML = "Not Logged In";

    }

});

document
.getElementById("loginButton")
.addEventListener("click", login);

document
.getElementById("inspectButton")
.addEventListener("click", inspectPrompt);

checkBackend();

chrome.storage.local.get(["jwt"], (result) => {

    console.log("JWT:");

    console.log(result.jwt);

});

document.getElementById("logoutButton").addEventListener("click", () => {

    chrome.storage.local.remove(["jwt", "user"], () => {

        location.reload();

    });

});