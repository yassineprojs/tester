let injected = false;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "toggleAnalysis") {
    if (!injected) {
      injectReactApp();
      injected = true;
    } else {
      toggleAnalysisVisibility();
    }
    sendResponse({ status: "success" });
  }
  return true;
});

function injectReactApp() {
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("assets/securityAnalysis.js");
  script.onload = () => {
    script.remove(); // remove the script element after it has loaded
  };
  (document.head || document.documentElement).appendChild(script);
}

function toggleAnalysisVisibility() {
  const analysisRoot = document.getElementById("security-analysis-root");
  if (analysisRoot) {
    analysisRoot.style.display =
      analysisRoot.style.display === "none" ? "block" : "none";
  }
}
