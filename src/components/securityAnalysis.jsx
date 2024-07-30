import React, { useState, useEffect } from "react";

function SecurityAnalysis() {
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [currentTabId, setCurrentTabId] = useState(null);
  const [expandedSection, setExpandedSection] = useState(null);

  useEffect(() => {
    const handleMessage = (message) => {
      if (message.action === "analysisStarted") {
        setAnalysisResult(null);
        setLoading(true);
        setCurrentTabId(message.tabId);
      } else if (
        message.action === "analysisComplete" &&
        message.tabId === currentTabId
      ) {
        setAnalysisResult(message.result);
        setLoading(false);
      }
    };

    chrome.runtime.onMessage.addListener(handleMessage);

    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (tabs[0]) {
        setCurrentTabId(tabs[0].id);
        chrome.storage.local.get(
          ["currentAnalysisTabId", `analysisResult_${tabs[0].id}`],
          (result) => {
            if (
              result.currentAnalysisTabId === tabs[0].id &&
              result[`analysisResult_${tabs[0].id}`]
            ) {
              setAnalysisResult(result[`analysisResult_${tabs[0].id}`]);
              setLoading(false);
            } else {
              chrome.runtime.sendMessage({
                action: "startAnalysis",
                tabId: tabs[0].id,
              });
            }
          }
        );
      } else {
        setError("No active tab found");
        setLoading(false);
      }
    });

    return () => {
      chrome.runtime.onMessage.removeListener(handleMessage);
    };
  }, [currentTabId]);

  const handleReanalyze = () => {
    setLoading(true);
    setAnalysisResult(null);
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (tabs[0]) {
        setCurrentTabId(tabs[0].id);
        chrome.runtime.sendMessage({
          action: "startAnalysis",
          tabId: tabs[0].id,
        });
      } else {
        setError("No active tab found");
        setLoading(false);
      }
    });
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  const calculateOverallScore = (result) => {
    const scores = [
      result.serverLeakage.score,
      result.sqlInjection.score,
      result.xss.score,
    ];
    return (scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(1);
  };

  return (
    <div className="security-analysis-popup">
      {error ? (
        <div className="error-message">{error}</div>
      ) : analysisResult ? (
        <>
          <pre className="security-analysis-result">
            {JSON.stringify(analysisResult, null, 2)}
          </pre>
          <button onClick={handleReanalyze}>Reanalyze</button>
        </>
      ) : (
        <div>Analysis in progress...</div>
      )}
    </div>
  );
}

export default SecurityAnalysis;
