import React, { useRef } from "react";
import { useGLTF } from "@react-three/drei";
import { MathUtils } from "three";
import { useFrame } from "@react-three/fiber";
import { useAIAssistant } from "../hooks/useAIAssistant";

export default function Assistant({ ...props }) {
  const { scene } = useGLTF("/models/modelSpeakMove.glb");
  const { currentMessage } = useAIAssistant();
  const meshRef = useRef();

  const lerpMorphTarget = (target, value, speed = 0.1) => {
    scene.traverse((child) => {
      if (child.isSkinnedMesh && child.morphTargetDictionary) {
        const index = child.morphTargetDictionary[target];
        if (
          index !== undefined &&
          child.morphTargetInfluences[index] !== undefined
        ) {
          child.morphTargetInfluences[index] = MathUtils.lerp(
            child.morphTargetInfluences[index],
            value,
            speed
          );
        }
      }
    });
  };

  useFrame(() => {
    // Reset morph targets
    for (let i = 0; i <= 21; i++) {
      lerpMorphTarget(i, 0, 0.1);
    }

    if (currentMessage?.visemes && currentMessage?.audioPlayer) {
      const currentTime = currentMessage.audioPlayer.currentTime * 1000;
      for (let i = currentMessage.visemes.length - 1; i >= 0; i--) {
        const [time, visemeId] = currentMessage.visemes[i];
        if (currentTime >= time) {
          lerpMorphTarget(visemeId, 1, 0.2);
          break;
        }
      }
    }
  });

  return <primitive object={scene} ref={meshRef} {...props} />;
}

useGLTF.preload("/models/modelSpeakMove.glb");
