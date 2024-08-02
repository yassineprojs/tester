import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { CircularProgressbar, buildStyles } from "react-circular-progressbar";
import "react-circular-progressbar/dist/styles.css";
import {
  FaServer,
  FaLock,
  FaShieldAlt,
  FaExclamationTriangle,
  FaInfoCircle,
} from "react-icons/fa";

function SecurityAnalysis() {
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [currentTabId, setCurrentTabId] = useState(null);
  const [expandedSections, setExpandedSections] = useState({});

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

  const toggleSection = (section) => {
    setExpandedSections((prev) => ({ ...prev, [section]: !prev[section] }));
  };

  const getScoreColor = (score) => {
    if (score >= 8) return "#4caf50";
    if (score >= 6) return "#ff9800";
    return "#f44336";
  };

  const renderScoreSection = (title, data, icon) => {
    if (!data) return null;
    const isExpanded = expandedSections[title] || false;
    return (
      <motion.div
        className="score-section"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <div className="score-header" onClick={() => toggleSection(title)}>
          {icon}
          <h3>{title}</h3>
          <div
            className="score-indicator"
            style={{ color: getScoreColor(data.score) }}
          >
            {data.score.toFixed(1)}
          </div>
          <motion.span
            className="arrow"
            animate={{ rotate: isExpanded ? 180 : 0 }}
            transition={{ duration: 0.3 }}
          >
            ▼
          </motion.span>
        </div>
        <AnimatePresence>
          {isExpanded && (
            <motion.div
              className="details"
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.3 }}
            >
              <p className="assessment">{data.overall_assessment}</p>
              {renderList("Warnings", data.warnings, <FaExclamationTriangle />)}
              {renderList(
                "Vulnerabilities",
                data.vulnerabilities,
                <FaExclamationTriangle />
              )}
              {renderList("Findings", data.findings, <FaInfoCircle />)}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    );
  };

  const renderList = (title, items, icon) => {
    if (items.length === 0) return null;
    return (
      <div className="list-section">
        <h4>
          {icon} {title}
        </h4>
        <ul>
          {items.map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>
      </div>
    );
  };

  if (loading) {
    return <div className="loading">Analyzing security...</div>;
  }

  if (error) {
    return <div className="error-message">{error}</div>;
  }

  if (!analysisResult) {
    return <div className="loading">Analysis in progress...</div>;
  }

  const result = analysisResult.result;
  const totalScore = result.total_score / 100; // total_score is out of 1000
  const highRiskIssues = result.scan_results.reduce(
    (acc, scan) =>
      acc +
      scan.server_leakage.vulnerabilities.length +
      scan.ssl_tls_scan.vulnerabilities.length +
      scan.xss_scan.vulnerabilities.length,
    0
  );
  const warnings = result.scan_results.reduce(
    (acc, scan) =>
      acc +
      scan.server_leakage.warnings.length +
      scan.ssl_tls_scan.warnings.length +
      scan.xss_scan.warnings.length,
    0
  );
  return (
    <div className="security-analysis-container">
      <h1>Security Analysis Results</h1>
      <div className="overview-section">
        <div className="score-chart">
          <CircularProgressbar
            value={totalScore * 10}
            text={`${totalScore.toFixed(1)}`}
            styles={buildStyles({
              textSize: "2rem",
              pathColor: getScoreColor(totalScore),
              textColor: getScoreColor(totalScore),
            })}
          />
        </div>
        <div className="quick-stats">
          <div className="stat">
            <FaExclamationTriangle />
            <span>{highRiskIssues} high-risk issues</span>
          </div>
          <div className="stat">
            <FaInfoCircle />
            <span>{warnings} warnings</span>
          </div>
        </div>
      </div>
      {result.scan_results.map((scan, index) => (
        <div key={index} className="scan-result">
          <h2>{scan.url}</h2>
          {renderScoreSection(
            "Server Leakage",
            scan.server_leakage,
            <FaServer />
          )}
          {renderScoreSection(
            "SSL/TLS Security",
            scan.ssl_tls_scan,
            <FaLock />
          )}
          {renderScoreSection("XSS Protection", scan.xss_scan, <FaShieldAlt />)}
        </div>
      ))}
      <div className="scanned-pages">
        <h3>Scanned Pages</h3>
        <ul>
          {result.scanned_pages.map((page, index) => (
            <li key={index}>{page}</li>
          ))}
        </ul>
      </div>
      <button className="reanalyze-button" onClick={handleReanalyze}>
        Reanalyze
      </button>
    </div>
  );
}

export default SecurityAnalysis;
