import React from "react";
import { interpolate, useCurrentFrame } from "remotion";
import { COLORS } from "../theme";

/**
 * ClickRipple — a short expanding ring + flash at a point, triggered when the
 * current frame passes `at`. Self-contained; place absolutely inside a scene.
 */
export const ClickRipple: React.FC<{
  x: number;
  y: number;
  at: number;
  color?: string;
  size?: number;
}> = ({ x, y, at, color = COLORS.blueBright, size = 120 }) => {
  const frame = useCurrentFrame();
  const local = frame - at;
  const DURATION = 26;

  if (local < 0 || local > DURATION) return null;

  const scale = interpolate(local, [0, DURATION], [0.2, 1], {
    extrapolateRight: "clamp",
  });
  const opacity = interpolate(local, [0, 6, DURATION], [0.0, 0.7, 0], {
    extrapolateRight: "clamp",
  });

  return (
    <div
      style={{
        position: "absolute",
        left: x,
        top: y,
        width: size,
        height: size,
        marginLeft: -size / 2,
        marginTop: -size / 2,
        borderRadius: "50%",
        border: `2px solid ${color}`,
        transform: `scale(${scale})`,
        opacity,
        pointerEvents: "none",
        boxShadow: `0 0 24px ${color}`,
      }}
    />
  );
};
