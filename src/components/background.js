chrome.action.onClicked.addListener((tab) => {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    chrome.tabs.sendMessage(
      tabs[0].id,
      { action: "toggleAnalysis" },
      function (response) {
        if (chrome.runtime.lastError) {
          console.log(chrome.runtime.lastError.message);
          // Handle the error, maybe inject the content script if it's not there
          chrome.scripting.executeScript(
            {
              target: { tabId: tabs[0].id },
              files: ["content.js"],
            },
            () => {
              if (chrome.runtime.lastError) {
                console.error(chrome.runtime.lastError.message);
              } else {
                // Try sending the message again after injecting the script
                chrome.tabs.sendMessage(tabs[0].id, {
                  action: "toggleAnalysis",
                });
              }
            }
          );
        }
      }
    );
  });
});
