console.log("background script loaded");
let analysisInProgress = false;
const iconUrl = chrome.runtime.getURL("images/icon-128.png");

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

chrome.notifications.onClicked.addListener((notificationId) => {
  if (notificationId === "analysis-complete") {
    chrome.tabs.create({ url: chrome.runtime.getURL("index.html") });
  }
});

function startAnalysis(tab) {
  analysisInProgress = true;
  chrome.notifications.create({
    type: "basic",
    title: "Security Analysis",
    iconUrl: iconUrl,
    message: "Starting security analysis. Please wait...",
    priority: 2,
  });

  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    chrome.scripting.executeScript(
      {
        target: { tabId: tabs[0].id },
        function: getPageUrl,
      },
      async (injectionResults) => {
        if (chrome.runtime.lastError) {
          console.error(chrome.runtime.lastError.message);
          analysisInProgress = false;
          return;
        }

        const url = injectionResults[0].result;
        try {
          const result = await fetch("http://localhost:3000/security-check", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ url: url }),
          }).then((res) => res.json());

          chrome.storage.local.set({ analysisResult: result }, () => {
            analysisInProgress = false;
            chrome.runtime.sendMessage({
              action: "analysisComplete",
              result: result,
            });
            chrome.notifications.create("analysis-complete", {
              type: "basic",
              title: "Security Analysis Complete",
              iconUrl: iconUrl,
              message: "Click to view the results",
              priority: 2,
            });
          });
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
  });
}

function getPageUrl() {
  return window.location.href;
}
