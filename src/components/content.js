console.log("Content script loaded"); // In content.js

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "getPageUrl") {
    sendResponse({ url: window.location.href });
  }
  return true;
});
