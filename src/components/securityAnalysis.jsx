import React, { useState, useEffect } from "react";
import ReactDOM from "react-dom/client";
import { Experience } from "./Experience";
import { analyseCurrentPage } from "../services/aiSetup";
import { useAIAssistant } from "../hooks/useAIAssistant";

function SecurityAnalysis() {
  const [result, setResult] = useState("");
  const [question, setQuestion] = useState("");
  const [showAnalysis, setShowAnalysis] = useState(true);
  const { askAI, messages, currentMessage, loading } = useAIAssistant();

  useEffect(() => {
    handleAnalyze();
  }, []);

  const toggleAnalysis = () => {
    setShowAnalysis(!showAnalysis);
  };

  const handleAnalyze = async () => {
    try {
      const data = await analyseCurrentPage();
      setResult(JSON.stringify(data, null, 2));
    } catch (error) {
      console.error("Error", error);
      setResult("Error occured durin analysis");
    }
  };

  const handleAskAi = async () => {
    if (!question) return;
    await askAI(question, result);
    setQuestion(""); // Clear the question input after asking
  };

  return (
    <div
      className="security-analysis-overlay"
      style={{ display: showAnalysis ? "block" : "none" }}
    >
      <Experience />
      <div className="security-analysis-ui">
        <button onClick={handleAnalyze}>Analyze current Page</button>
        <button onClick={toggleAnalysis}>Toggle Analysis</button>
        <pre className="security-analysis-result">{result}</pre>
        <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="Ask a question about the security analysis"
        />

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

function render() {
  const root = document.createElement("div");
  root.id = "security-analysis-root";
  document.body.appendChild(root);
  const reactRoot = ReactDOM.createRoot(root);
  reactRoot.render(React.createElement(SecurityAnalysis));
}

render();
