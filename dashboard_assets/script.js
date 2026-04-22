// script.js - External JavaScript for Sentinel Dashboard
console.log("Sentinel Dashboard initialized.");

function scrollToBottom(containerId) {
    var container = document.getElementById(containerId);
    if (container) {
        container.scrollTop = container.scrollHeight;
    }
}

// Automatically scroll the alerts container
setTimeout(function () {
    scrollToBottom('alerts-body');
}, 100);
