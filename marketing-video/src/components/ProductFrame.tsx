import React from "react";
import { COLORS, EASE, FONT_MONO } from "../theme";

/**
 * ProductFrame — outer "app window" chrome used to host mock ConfigTrace UI.
 * Optional header and sidebar slots compose the full control-plane layout.
 */
export const ProductFrame: React.FC<{
  width?: number;
  height?: number;
  url?: string;
  header?: React.ReactNode;
  sidebar?: React.ReactNode;
  children?: React.ReactNode;
  style?: React.CSSProperties;
}> = ({
  width = 1480,
  height = 820,
  url = "app.configtrace.org",
  header,
  sidebar,
  children,
  style,
}) => {
  return (
    <div
      style={{
        width,
        height,
        borderRadius: EASE.radiusLg,
        overflow: "hidden",
        background: COLORS.bgSecondary,
        border: `1px solid ${COLORS.cardBorder}`,
        boxShadow: EASE.shadow,
        display: "flex",
        flexDirection: "column",
        ...style,
      }}
    >
      {/* Window chrome */}
      <div
        style={{
          height: 40,
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "0 16px",
          background: "rgba(8, 11, 16, 0.92)",
          borderBottom: `1px solid ${COLORS.cardBorder}`,
        }}
      >
        <span style={dot("#FF5F57")} />
        <span style={dot("#FEBC2E")} />
        <span style={dot("#28C840")} />
        <div
          style={{
            marginLeft: 14,
            flex: 1,
            maxWidth: 360,
            height: 22,
            borderRadius: 7,
            background: "rgba(148,163,184,0.08)",
            display: "flex",
            alignItems: "center",
            padding: "0 12px",
            fontFamily: FONT_MONO,
            fontSize: 11,
            color: COLORS.textFaint,
          }}
        >
          {url}
        </div>
      </div>

      {/* Body: optional sidebar + content */}
      <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
        {sidebar ? (
          <div
            style={{
              width: 220,
              borderRight: `1px solid ${COLORS.cardBorder}`,
              background: "rgba(8, 11, 16, 0.55)",
              flexShrink: 0,
            }}
          >
            {sidebar}
          </div>
        ) : null}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          {header}
          <div style={{ flex: 1, padding: 26, minHeight: 0 }}>{children}</div>
        </div>
      </div>
    </div>
  );
};

const dot = (c: string): React.CSSProperties => ({
  width: 11,
  height: 11,
  borderRadius: 6,
  background: c,
  display: "inline-block",
});
