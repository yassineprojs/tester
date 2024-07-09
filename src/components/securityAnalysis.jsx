import React, { useState, useEffect } from "react";
import ReactDOM from "react-dom/client";
import { Experience } from "./Experience";
function SecurityAnalysis() {
  // const [result, setResult] = useState("");
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
  // useEffect(() => {
  //   analyseCurrentPage();
  // }, []);
  return (
    <div style={{ width: "100vw", height: "100vh", overflow: "hidden" }}>
      <Experience />
      {/* <button onClick={analyseCurrentPage}>Analyze current Page</button>
      <pre>{result}</pre> */}
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
