import React, { useRef, useState, useEffect } from "react";
import { OrbitControls, Gltf, Environment, useGLTF } from "@react-three/drei";
import { Canvas } from "@react-three/fiber";
import Assistant from "./Avatar.jsx";

export const Experience = () => {
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
      <Assistant scale={1.5} />
    </Canvas>
  );
};
