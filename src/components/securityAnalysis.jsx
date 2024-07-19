import React, { useState, useEffect } from "react";
import ReactDOM from "react-dom/client";
import { Experience } from "./Experience";
// import { useAIAssistant } from "../hooks/useAIAssistant";

function SecurityAnalysis() {
  // const [result, setResult] = useState("");
  // const [question, setQuestion] = useState("");
  // const { askAI, messages, currentMessage, loading } = useAIAssistant();

  // useEffect(() => {
  //   handleAnalyze();
  // }, []);

  // const handleAnalyze = async () => {
  //   try {
  //     const data = await analyseCurrentPage();
  //     setResult(JSON.stringify(data, null, 2));
  //   } catch (error) {
  //     console.error("Error", error);
  //     setResult("Error occured durin analysis");
  //   }
  // };

  // const handleAskAi = async () => {
  //   if (!question) return;
  //   await askAI(question, result);
  //   setQuestion(""); // Clear the question input after asking
  // };
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const handleAnalysisComplete = (message) => {
      if (message.action === "analysisComplete") {
        setAnalysisResult(message.result);
      }
    };

    chrome.runtime.onMessage.addListener(handleAnalysisComplete);

    if (chrome && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(["analysisResult"], (result) => {
        if (result.analysisResult) {
          setAnalysisResult(result.analysisResult);
        } else {
          setError("No analysis result found. Please run the analysis first.");
        }
      });
    } else {
      setError(
        "Chrome storage is not available. Are you running this in a browser extension context?"
      );
    }

    return () => {
      chrome.runtime.onMessage.removeListener(handleAnalysisComplete);
    };
  }, []);

  return (
    <div className="security-analysis-overlay">
      <Experience />
      <div className="security-analysis-ui">
        {/* <button onClick={handleAnalyze}>Analyze current Page</button> */}
        {/* <pre className="security-analysis-result">{result}</pre> */}
        {error ? (
          <div className="error-message">{error}</div>
        ) : (
          <pre className="security-analysis-result">
            {analysisResult
              ? JSON.stringify(analysisResult, null, 2)
              : "Loading..."}
          </pre>
        )}
        {/* <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="Ask a question about the security analysis"
        /> */}

        {/* <button onClick={handleAskAi} disabled={loading}>
          {loading ? "Processing..." : "Ask AI"}
        </button>
        {messages.map((message) => (
          <div key={message.id}>
            <p>Q: {message.question}</p>
            <p>A: {message.answer}</p>
            {message.audioPlayer && (
              <button onClick={() => message.audioPlayer.play()}>
                Play Audio
              </button>
            )}
          </div>
        ))} */}
      </div>
    </div>
  );
}

export default SecurityAnalysis;
