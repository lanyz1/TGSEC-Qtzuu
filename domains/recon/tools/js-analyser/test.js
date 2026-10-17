// TODO: Fix security issues in this file
// SECURITY: This file contains hardcoded credentials - remove before production

// Hardcoded API Keys
const apiKey = "AIzaEXAMPLE";
const awsAccessKey = "AKIAIOSFODNN7EXAMPLE";
const awsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const stripeKey = "sk_live_REDACTED";
const githubToken = "ghp_EXAMPLE";

// Hardcoded Credentials
const username = "admin";
const password = "SuperSecretPassword123!";
const dbPassword = "database_password_2024";
const email = "admin@example.com";

// API Configuration
const baseURL = "https://api.example.com/v1";
const apiUrl = "https://api.secureapp.com/endpoint";

// XSS Vulnerabilities
function displayUserInput(userInput) {
    document.getElementById("content").innerHTML = userInput; // XSS: innerHTML with user input
    return userInput;
}

function renderContent(content) {
    const div = document.createElement("div");
    div.outerHTML = content; // XSS: outerHTML assignment
    return div;
}

function writeToPage(data) {
    document.write("<h1>" + data + "</h1>"); // XSS: document.write
}

function evalUserCode(userCode) {
    eval(userCode); // XSS: eval with user input - CRITICAL
}

// React XSS
function ReactComponent({ userContent }) {
    return <div dangerouslySetInnerHTML={{ __html: userContent }} />; // XSS: React dangerouslySetInnerHTML
}

// jQuery XSS
function updateContent(content) {
    $("#userContent").html(content); // XSS: jQuery .html()
    $("#sidebar").append(content); // XSS: jQuery .append()
}

// Location manipulation
function redirect(url) {
    location.href = url; // Potential XSS
    location.hash = "#" + url; // Potential XSS
}

// XSS Functions
function processUserData(userData) {
    const element = document.getElementById("output");
    element.innerHTML = userData.name; // Function with innerHTML
}

const renderUser = function(userInput) {
    document.getElementById("user").innerHTML = userInput; // Arrow function with DOM manipulation
};

// API Endpoints
fetch("/api/users/123");
fetch(`/api/data/${userId}`);
axios.get("/api/products");
axios.post("/api/orders", { data: orderData });
$.ajax({
    url: "/api/checkout",
    method: "POST"
});
$.get("/api/cart");
$.getJSON("/api/items");

// URL Parameters - Query Strings
const apiUrl1 = "/app?key=kjhsdjkfhsjk";
const apiUrl2 = "/login?email=user@example.com&password=secret123";
const apiUrl3 = "/download?file=document.pdf&token=abc123";
const apiUrl4 = "/api/data?id=12345&session=xyz789";
const apiUrl5 = "https://api.example.com/v1/users?uid=999&access_token=token123";
fetch("/app?key=kjhsdjkfhsjk&action=view");
location.href = "/dashboard?user=admin&role=super";
window.location.search = "?email=test@test.com&key=secret";

const xhr = new XMLHttpRequest();
xhr.open("GET", "/api/status");
xhr.send();

// API Paths
const endpoints = {
    login: "/api/v1/auth/login",
    logout: "/api/v1/auth/logout",
    users: "/api/v2/users",
    products: "/api/products",
    orders: "/v3/orders"
};

// Parameters
function getUserData(userId, apiKey) {
    return fetch(`/api/users/${userId}?key=${apiKey}`);
}

function processRequest(params) {
    const { username, password, token } = params;
    return axios.post("/api/login", { username, password, token });
}

const urlParams = new URLSearchParams(window.location.search);
const apiKeyParam = urlParams.get("key");

// Paths and Directories
const configPath = "/config/app.json";
const assetPath = "./assets/images/logo.png";
const scriptPath = "../scripts/utils.js";
const dataDir = "/data/exports/";
const logFile = "logs/application.log";

// HACK: Temporary fix for authentication
function authenticate(user, pass) {
    if (user === "admin" && pass === "admin123") {
        return true; // BUG: Hardcoded credentials
    }
    return false;
}

// FIXME: Remove debug credentials
const debugUser = "debug";
const debugPass = "debug123";

// NOTE: This endpoint is deprecated
fetch("/api/old-endpoint");

// WARNING: This function uses eval - security risk
function executeDynamicCode(code) {
    const result = eval(code);
    return result;
}

// Suspicious comment about secret
// secret: admin_backdoor_key_2024
// token: temp_dev_token_xyz789

// Email addresses in code
const supportEmail = "support@company.com";
const adminEmail = "admin@secureapp.io";
const contactEmail = "contact@example.org";

// JWT Token (example)
const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// Event handlers (potential XSS)
document.getElementById("button").onclick = function() {
    document.getElementById("output").innerHTML = userInput;
};

window.onerror = function(msg, url, line) {
    document.write("Error: " + msg); // XSS: document.write in error handler
};

// More API calls
const apiClient = {
    baseURL: "https://api.production.com",
    endpoints: {
        auth: "/v1/auth",
        data: "/v2/data",
        upload: "/v1/upload"
    }
};

// Function parameters
function makeRequest(method, endpoint, data, headers) {
    return fetch(endpoint, {
        method: method,
        body: JSON.stringify(data),
        headers: headers
    });
}

// URL construction
const apiEndpoint = baseURL + "/users/" + userId + "/profile";
const fullUrl = "https://api.example.com" + "/data?key=" + apiKey;

// Path manipulation
const filePath = "/uploads/" + fileName;
const imagePath = "../images/" + imageName;
const scriptPath2 = "./scripts/" + scriptName + ".js";

