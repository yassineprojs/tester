import React from "react";
import ReactDOM from "react-dom/client";
import SecurityAnalysis from "./components/securityAnalysis";
import "./index.css";

ReactDOM.createRoot(document.getElementById("app")).render(
  <React.StrictMode>
    <SecurityAnalysis />
  </React.StrictMode>
);
