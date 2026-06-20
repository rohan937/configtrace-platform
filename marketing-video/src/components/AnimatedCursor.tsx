import React from "react";
import { Easing, interpolate, useCurrentFrame } from "remotion";
import { COLORS, FONT_SANS } from "../theme";
import { ClickRipple } from "./ClickRipple";

export type CursorKey = {
  /** Local frame (relative to the scene) at which the cursor reaches (x, y). */
  frame: number;
  x: number;
  y: number;
  /** Emit a click ripple + press animation when reaching this keyframe. */
  click?: boolean;
  /** Show a soft pulsing hover ring around the cursor at this keyframe. */
  hover?: boolean;
  /** Optional small label shown beside the cursor (e.g. "click"). */
  label?: string;
};

/**
 * AnimatedCursor — a reusable, keyframed product-demo cursor.
 *
 * Movement eases between keyframes; clicks trigger a press + ClickRipple.
 * Drives the "real walkthrough" feel across scenes 2–8.
 */
export const AnimatedCursor: React.FC<{
  keys: CursorKey[];
  color?: string;
}> = ({ keys, color = COLORS.blueBright }) => {
  const frame = useCurrentFrame();
  const sorted = [...keys].sort((a, b) => a.frame - b.frame);

  const first = sorted[0];
  const last = sorted[sorted.length - 1];

  // Position: piecewise eased interpolation across keyframes.
  let x = first.x;
  let y = first.y;

  if (frame <= first.frame) {
    x = first.x;
    y = first.y;
  } else if (frame >= last.frame) {
    x = last.x;
    y = last.y;
  } else {
    for (let i = 0; i < sorted.length - 1; i++) {
      const a = sorted[i];
      const b = sorted[i + 1];
      if (frame >= a.frame && frame <= b.frame) {
        const t = interpolate(frame, [a.frame, b.frame], [0, 1], {
          easing: Easing.bezier(0.4, 0, 0.2, 1),
          extrapolateLeft: "clamp",
          extrapolateRight: "clamp",
        });
        x = a.x + (b.x - a.x) * t;
        y = a.y + (b.y - a.y) * t;
        break;
      }
    }
  }

  // Press animation: brief scale-down right at a click keyframe.
  const clickKeys = sorted.filter((k) => k.click);
  let press = 1;
  for (const k of clickKeys) {
    const d = frame - k.frame;
    if (d >= -2 && d <= 8) {
      press = Math.min(
        press,
        interpolate(d, [-2, 1, 8], [1, 0.82, 1], {
          extrapolateLeft: "clamp",
          extrapolateRight: "clamp",
        }),
      );
    }
  }

  // Active label: show near a click OR hover keyframe if provided.
  const labelKeys = sorted.filter((k) => k.label);
  const activeLabelKey = labelKeys.find(
    (k) => frame >= k.frame - 4 && frame <= k.frame + 22,
  );

  // Hover ring: a soft pulsing ring while the cursor dwells on a hover key.
  const hoverKeys = sorted.filter((k) => k.hover);
  let hoverStrength = 0;
  let hoverAt = { x, y };
  for (const k of hoverKeys) {
    const d = frame - k.frame;
    if (d >= -6 && d <= 34) {
      const s = interpolate(d, [-6, 4, 24, 34], [0, 1, 1, 0], {
        extrapolateLeft: "clamp",
        extrapolateRight: "clamp",
      });
      if (s > hoverStrength) {
        hoverStrength = s;
        hoverAt = { x: k.x, y: k.y };
      }
    }
  }
  const hoverPulse = interpolate(Math.sin(frame / 6), [-1, 1], [0.85, 1.12]);

  return (
    <>
      {clickKeys.map((k, i) => (
        <ClickRipple key={i} x={k.x} y={k.y} at={k.frame} color={color} />
      ))}

      {hoverStrength > 0 ? (
        <div
          style={{
            position: "absolute",
            left: hoverAt.x,
            top: hoverAt.y,
            width: 46,
            height: 46,
            marginLeft: -23,
            marginTop: -23,
            borderRadius: "50%",
            border: `2px solid ${color}`,
            opacity: hoverStrength * 0.7,
            transform: `scale(${hoverPulse})`,
            boxShadow: `0 0 18px ${color}`,
            pointerEvents: "none",
            zIndex: 49,
          }}
        />
      ) : null}

      <div
        style={{
          position: "absolute",
          left: x,
          top: y,
          transform: `scale(${press})`,
          transformOrigin: "top left",
          pointerEvents: "none",
          zIndex: 50,
          filter: "drop-shadow(0 6px 14px rgba(2,6,18,0.6))",
        }}
      >
        <CursorGlyph color={color} />
        {activeLabelKey?.label ? (
          <div
            style={{
              position: "absolute",
              left: 26,
              top: 22,
              padding: "3px 9px",
              borderRadius: 8,
              background: color,
              color: COLORS.textInk,
              fontFamily: FONT_SANS,
              fontWeight: 700,
              fontSize: 12,
              letterSpacing: 0.2,
              whiteSpace: "nowrap",
            }}
          >
            {activeLabelKey.label}
          </div>
        ) : null}
      </div>
    </>
  );
};

const CursorGlyph: React.FC<{ color: string }> = ({ color }) => (
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
    <path
      d="M5 3L5 21L10 16L13.5 23.5L17 22L13.5 14.5L21 14L5 3Z"
      fill="white"
      stroke={color}
      strokeWidth="1.5"
      strokeLinejoin="round"
    />
  </svg>
);
