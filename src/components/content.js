let injected = false;
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "toggleAnalysis" && !injected) {
    injectReactApp();
    injected = true;
  }
});

function injectReactApp() {
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("assets/securityAnalysis.js");
  document.body.appendChild(script);
}
