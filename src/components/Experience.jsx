import React, { useRef, useState, useEffect } from "react";
import { OrbitControls, Gltf, Environment, useGLTF } from "@react-three/drei";
import { Canvas } from "@react-three/fiber";
// import Assistant from "./Avatar.jsx";

function Assistant({ modelUrl, ...props }) {
  const { scene } = useGLTF("/models/modelSpeakMove.glb");
  return <primitive object={scene} {...props} />;
}

export const Experience = () => {
  const [modelUrl, setModelUrl] = useState(null);

  useEffect(() => {
    if (
      typeof chrome !== "undefined" &&
      chrome.runtime &&
      chrome.runtime.getURL
    ) {
      // Chrome extension environment
      const url = chrome.runtime.getURL("models/modelSpeakMove.glb");
      setModelUrl(url);
    } else {
      // Non-extension environment (e.g., development)
      console.warn(
        "Not running as a Chrome extension. Using fallback model URL."
      );
      setModelUrl("/models/modelSpeakMove.glb");
    }
  }, []);

  if (!modelUrl) return null;
  return (
    <Canvas
      style={{
        background: "rgba(128, 128, 128, 0.5)",
        position: "fixed",
        top: 0,
        left: 0,
        width: "100vw",
        height: "100vh",
        overflow: "hidden",
        zIndex: 99999,
        pointerEvents: "none",
      }}
    >
      <Environment preset="sunset" />
      <ambientLight intensity={0.8} color="pink" />
      <OrbitControls />
      <Assistant scale={1.5} modelUrl={modelUrl} />
    </Canvas>
  );
};
