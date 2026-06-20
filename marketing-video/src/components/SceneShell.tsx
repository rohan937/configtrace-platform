import React from "react";
import {
  AbsoluteFill,
  Easing,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { COLORS, FONT_SANS } from "../theme";
import { hexA } from "./ui-mocks";

/** Dark control-plane backdrop: base color, subtle grid, ambient glow. */
export const SceneShell: React.FC<{
  glow?: "blue" | "cyan" | "amber" | "red" | "green" | "violet";
  children?: React.ReactNode;
}> = ({ glow = "blue", children }) => {
  const glowColor =
    glow === "cyan"
      ? COLORS.cyan
      : glow === "amber"
        ? COLORS.amber
        : glow === "red"
          ? COLORS.red
          : glow === "green"
            ? COLORS.green
            : glow === "violet"
              ? COLORS.violet
              : COLORS.blue;

  return (
    <AbsoluteFill style={{ background: COLORS.bgBase }}>
      {/* subtle grid */}
      <AbsoluteFill
        style={{
          backgroundImage: `linear-gradient(${COLORS.grid} 1px, transparent 1px), linear-gradient(90deg, ${COLORS.grid} 1px, transparent 1px)`,
          backgroundSize: "56px 56px",
        }}
      />
      {/* ambient glow */}
      <AbsoluteFill
        style={{
          background: `radial-gradient(1200px 700px at 50% -8%, ${hexA(glowColor, 0.16)}, transparent 60%)`,
        }}
      />
      <AbsoluteFill
        style={{
          background: `radial-gradient(900px 600px at 90% 110%, ${hexA(COLORS.cyan, 0.07)}, transparent 60%)`,
        }}
      />
      {children}
    </AbsoluteFill>
  );
};

/** Bottom-anchored caption line that fades/slides in. */
export const Caption: React.FC<{
  children: React.ReactNode;
  appearAt?: number;
  y?: number;
}> = ({ children, appearAt = 6, y = 86 }) => {
  const frame = useCurrentFrame();
  const o = interpolate(frame, [appearAt, appearAt + 14], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const ty = interpolate(frame, [appearAt, appearAt + 14], [12, 0], {
    easing: Easing.out(Easing.cubic),
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  return (
    <div
      style={{
        position: "absolute",
        bottom: y,
        left: 0,
        right: 0,
        textAlign: "center",
        opacity: o,
        transform: `translateY(${ty}px)`,
      }}
    >
      <span
        style={{
          fontFamily: FONT_SANS,
          fontSize: 22,
          fontWeight: 500,
          color: COLORS.textMuted,
          letterSpacing: 0.2,
        }}
      >
        {children}
      </span>
    </div>
  );
};

/** Spring-based mount helper: returns {opacity, translateY} for entrance. */
export const useEntrance = (
  delay = 0,
  distance = 24,
): { opacity: number; transform: string } => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const s = spring({
    frame: frame - delay,
    fps,
    config: { damping: 200, stiffness: 120, mass: 0.7 },
  });
  return {
    opacity: s,
    transform: `translateY(${(1 - s) * distance}px)`,
  };
};
