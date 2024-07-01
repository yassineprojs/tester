import React, { useState, useEffect } from "react";
import ReactDOM from "react-dom/client";
function SecurityAnalysis() {
  const [result, setResult] = useState("");
  const analyseCurrentPage = () => {
    const url = window.location.href;
    // Send a POST request to the local server with the url of the active tab
    fetch("http://localhost:3000/security-check", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: url }),
    })
      .then((response) => response.json()) //convert the response to JSON
      .then((data) => {
        setResult(JSON.stringify(data, null, 2));
      })
      .catch((error) => {
        console.error("Error", error);
        setResult("Error occured during analysis");
      });
  };
  useEffect(() => {
    analyseCurrentPage();
  }, []);
  return (
    <div>
      <h1>Security Analysis</h1>
      <button onClick={analyseCurrentPage}>Analyze current Page</button>
      <pre>{result}</pre>
    </div>
  );
}

function render() {
  const overlayRoot = document.getElementById("security-analysis-overlay");
  const reactRoot = ReactDOM.createRoot(overlayRoot);
  reactRoot.render(React.createElement(SecurityAnalysis));
}

render();
