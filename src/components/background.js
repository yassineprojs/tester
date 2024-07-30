console.log("background script loaded");
let analysisInProgress = false;
const iconUrl = chrome.runtime.getURL("images/icon-128.png");

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install" || details.reason === "update") {
    chrome.storage.local.clear(() => {
      console.log("Storage cleared on install/update");
    });
  }
});

chrome.action.onClicked.addListener((tab) => {
  if (analysisInProgress) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: iconUrl,
      title: "Security Analysis",
      message: "Analysis is already in progress. Please wait.",
      priority: 2,
    });
  } else {
    startAnalysis(tab);
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "startAnalysis") {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (tabs[0]) {
        startAnalysis(tabs[0]);
      }
    });
  }
});

function startAnalysis(tab) {
  if (analysisInProgress) {
    return;
  }

  analysisInProgress = true;

  chrome.storage.local.set({ currentAnalysisTabId: tab.id }, () => {
    console.log("Current analysis tab ID set:", tab.id);
  });

  chrome.runtime.sendMessage({ action: "analysisStarted", tabId: tab.id });

  chrome.scripting.executeScript(
    {
      target: { tabId: tab.id },
      function: getPageUrl,
    },
    async (injectionResults) => {
      if (chrome.runtime.lastError) {
        console.error(chrome.runtime.lastError.message);
        analysisInProgress = false;
        return;
      }

      const url = injectionResults[0].result;

      chrome.notifications.create({
        type: "basic",
        title: "Security Analysis",
        iconUrl: iconUrl,
        message: "Starting security analysis. Please wait...",
        priority: 2,
      });

      try {
        const result = await fetch("http://localhost:3000/security-check", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ url: url }),
        }).then((res) => res.json());

        chrome.storage.local.set(
          {
            [`analysisResult_${tab.id}`]: result,
            currentAnalysisTabId: tab.id,
          },
          () => {
            analysisInProgress = false;
            chrome.runtime.sendMessage({
              action: "analysisComplete",
              result,
              tabId: tab.id,
            });
            chrome.notifications.create("analysis-complete", {
              type: "basic",
              title: "Security Analysis Complete",
              iconUrl: iconUrl,
              message: "Results are now available in the extension popup",
              priority: 2,
            });
          }
        );
      } catch (error) {
        console.error("Analysis failed:", error);
        analysisInProgress = false;
        chrome.notifications.create({
          type: "basic",
          title: "Security Analysis Failed",
          iconUrl: iconUrl,
          message: "Unable to complete the analysis. Please try again.",
          priority: 2,
        });
      }
    }
  );
}

function getPageUrl() {
  return window.location.href;
}
