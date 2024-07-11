import React, { useState, useEffect } from "react";
import ReactDOM from "react-dom/client";
import { Experience } from "./Experience";
import { analyseCurrentPage, askAI } from "../services/aiSetup";

function SecurityAnalysis() {
  const [result, setResult] = useState("");
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState("");

  useEffect(() => {
    handleAnalyze();
  }, []);

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
    try {
      const response = await askAI(question, result);
      setAnswer(response);
    } catch (error) {
      console.error("Error", error);
      setAnswer("Error occured while asking AI");
    }
  };

  return (
    <div style={{ width: "100vw", height: "100vh", overflow: "hidden" }}>
      <Experience />
      <button onClick={handleAnalyze}>Analyze current Page</button>
      <pre>{result}</pre>
      <input
        type="text"
        value={question}
        onChange={(e) => setQuestion(e.target.value)}
        placeholder="Ask a sueqtion about the security analysis"
      />
      <button onClick={handleAskAi}>Ask Ai</button>
      <div>{answer}</div>
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

// const analyseCurrentPage = () => {
//   const url = window.location.href;
//   // Send a POST request to the local server with the url of the active tab
//   fetch("http://localhost:3000/security-check", {
//     method: "POST",
//     headers: {
//       "Content-Type": "application/json",
//     },
//     body: JSON.stringify({ url: url }),
//   })
//     .then((response) => response.json()) //convert the response to JSON
//     .then((data) => {
//       setResult(JSON.stringify(data, null, 2));
//     })
//     .catch((error) => {
//       console.error("Error", error);
//       setResult("Error occured during analysis");
//     });
// };
