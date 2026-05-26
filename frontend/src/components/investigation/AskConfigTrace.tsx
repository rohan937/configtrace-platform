"use client";

/**
 * AskConfigTrace panel — M58.9.
 *
 * Controlled question-and-answer panel for change investigation rooms.
 * Provides deterministic, grounded answers from existing ConfigTrace data.
 *
 * Design constraints:
 *   - No free-text input. Predefined question chips only.
 *   - No external API calls. All answers come from riskAssistant.ts.
 *   - Visible for medium / high / critical risk changes.
 *   - Shows a reduced question set for low / unknown risk.
 *   - "Summarize for my team" question includes a Copy button.
 */

import { useState } from "react";
import type { ChangeDetail } from "@/types";
import type { RemediationResult, FixPlanResult } from "@/lib/remediation";
import type { RemediationPreviewResult } from "@/lib/remediationPreview";
import {
  buildRiskAssistantContext,
  getAssistantQuestionsForChange,
  answerAssistantQuestion,
  type AssistantQuestionId,
  type AssistantResponse,
} from "@/lib/riskAssistant";

// ── Colour helpers ────────────────────────────────────────────────────────────

const CONFIDENCE_COLORS: Record<AssistantResponse["confidence"], string> = {
  high:   "#3ccf7e",
  medium: "#f5a623",
  low:    "#565b6e",
};

const CONFIDENCE_LABELS: Record<AssistantResponse["confidence"], string> = {
  high:   "High confidence",
  medium: "Medium confidence",
  low:    "Low confidence",
};

// ── Sub-components ────────────────────────────────────────────────────────────

function QuestionChip({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "5px 12px",
        fontSize: "12px",
        fontWeight: active ? 600 : 400,
        color: active ? "#e8eaf0" : "#8b90a0",
        background: active ? "#1e2535" : "transparent",
        border: active ? "1px solid #4f80f7" : "1px solid #2a2d38",
        borderRadius: "20px",
        cursor: "pointer",
        whiteSpace: "nowrap",
        transition: "all 0.12s ease",
        flexShrink: 0,
      }}
    >
      {label}
    </button>
  );
}

function GroundingFact({ fact }: { fact: string }) {
  return (
    <span
      style={{
        display: "inline-block",
        fontSize: "11px",
        color: "#565b6e",
        background: "#0e0f11",
        border: "1px solid #1e2030",
        borderRadius: "4px",
        padding: "2px 7px",
        marginRight: "4px",
        marginBottom: "4px",
      }}
    >
      {fact}
    </span>
  );
}

function AnswerCard({
  response,
  onCopy,
}: {
  response: AssistantResponse;
  onCopy?: () => void;
}) {
  const confColor = CONFIDENCE_COLORS[response.confidence];
  const confLabel = CONFIDENCE_LABELS[response.confidence];

  // Bullets: detect "Could be expected if:" framing and render as sections
  const isExpectedQuestion = response.question_id === "could_be_expected";

  return (
    <div
      style={{
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        padding: "16px",
        marginTop: "12px",
        animation: "fadeIn 0.15s ease",
      }}
    >
      {/* Header row: title + confidence badge */}
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: "12px",
          marginBottom: "10px",
        }}
      >
        <h3
          style={{
            fontSize: "13px",
            fontWeight: 600,
            color: "#e8eaf0",
            margin: 0,
            lineHeight: 1.4,
          }}
        >
          {response.title}
        </h3>
        <span
          style={{
            fontSize: "10px",
            color: confColor,
            border: `1px solid ${confColor}33`,
            borderRadius: "4px",
            padding: "2px 7px",
            whiteSpace: "nowrap",
            flexShrink: 0,
            letterSpacing: "0.03em",
          }}
        >
          {confLabel}
        </span>
      </div>

      {/* Prose answer */}
      <p
        style={{
          fontSize: "13px",
          color: "#b0b5c4",
          lineHeight: 1.7,
          margin: "0 0 12px",
        }}
      >
        {response.answer}
      </p>

      {/* Bullet points */}
      {response.bullets.length > 0 && (
        <ul
          role="list"
          style={{ margin: "0 0 12px", padding: 0, listStyle: "none" }}
        >
          {response.bullets.map((b, i) => {
            // Section headers for could_be_expected (lines ending in ":")
            const isSectionHeader =
              isExpectedQuestion && (b === "Could be expected if:" || b === "Needs review if:");
            const isSubItem = isExpectedQuestion && b.startsWith("  → ");

            if (isSectionHeader) {
              return (
                <li
                  key={i}
                  style={{
                    fontSize: "11px",
                    fontWeight: 600,
                    color: "#565b6e",
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    marginTop: i === 0 ? 0 : "10px",
                    marginBottom: "4px",
                  }}
                >
                  {b}
                </li>
              );
            }

            return (
              <li
                key={i}
                style={{
                  fontSize: "12px",
                  color: "#8b90a0",
                  lineHeight: 1.6,
                  display: "flex",
                  gap: "8px",
                  paddingBottom: "3px",
                  paddingLeft: isSubItem ? "8px" : "0",
                }}
              >
                <span
                  aria-hidden="true"
                  style={{ color: "#4f80f7", flexShrink: 0, marginTop: "1px" }}
                >
                  {isSubItem ? "·" : "·"}
                </span>
                <span>{isSubItem ? b.slice(4) : b}</span>
              </li>
            );
          })}
        </ul>
      )}

      {/* Grounding facts */}
      {response.grounding.length > 0 && (
        <div style={{ marginBottom: "10px" }}>
          <p
            style={{
              fontSize: "10px",
              color: "#3a3e50",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              margin: "0 0 5px",
            }}
          >
            Grounded from
          </p>
          <div style={{ display: "flex", flexWrap: "wrap" }}>
            {response.grounding.map((fact, i) => (
              <GroundingFact key={i} fact={fact} />
            ))}
          </div>
        </div>
      )}

      {/* Limitations */}
      {response.limitations.length > 0 && (
        <div
          style={{
            borderTop: "1px solid #1e2030",
            paddingTop: "10px",
            marginTop: "4px",
          }}
        >
          {response.limitations.map((lim, i) => (
            <p
              key={i}
              style={{
                fontSize: "11px",
                color: "#3a3e50",
                fontStyle: "italic",
                lineHeight: 1.5,
                margin: i === 0 ? "0" : "4px 0 0",
              }}
            >
              ℹ {lim}
            </p>
          ))}
        </div>
      )}

      {/* CTA row */}
      {(response.recommended_action_label || onCopy) && (
        <div
          style={{
            display: "flex",
            gap: "8px",
            marginTop: "12px",
            paddingTop: "10px",
            borderTop: "1px solid #1e2030",
            flexWrap: "wrap",
          }}
        >
          {response.recommended_action_label && response.anchor && (
            <a
              href={response.anchor}
              style={{
                fontSize: "12px",
                color: "#4f80f7",
                textDecoration: "none",
                padding: "4px 10px",
                border: "1px solid #4f80f733",
                borderRadius: "4px",
              }}
            >
              {response.recommended_action_label} →
            </a>
          )}
          {onCopy && (
            <button
              onClick={onCopy}
              style={{
                fontSize: "12px",
                color: "#8b90a0",
                background: "transparent",
                border: "1px solid #2a2d38",
                borderRadius: "4px",
                padding: "4px 10px",
                cursor: "pointer",
              }}
            >
              Copy summary
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface AskConfigTraceProps {
  change: ChangeDetail;
  remediation: RemediationResult;
  fixPlan: FixPlanResult;
  preview: RemediationPreviewResult;
  relatedChangesCount?: number;
}

export default function AskConfigTrace({
  change,
  remediation,
  fixPlan,
  preview,
  relatedChangesCount = 0,
}: AskConfigTraceProps) {
  const [activeQuestionId, setActiveQuestionId] = useState<AssistantQuestionId | null>(null);
  const [copied, setCopied] = useState(false);

  const ctx = buildRiskAssistantContext(
    change,
    remediation,
    fixPlan,
    preview,
    relatedChangesCount,
  );

  const questions = getAssistantQuestionsForChange(ctx);

  // Don't render for unknown risk (no data to ground answers)
  if (ctx.riskLevel === "unknown") return null;

  const activeResponse = activeQuestionId
    ? answerAssistantQuestion(activeQuestionId, ctx)
    : null;

  function handleQuestionClick(id: AssistantQuestionId) {
    setActiveQuestionId((prev) => (prev === id ? null : id));
    setCopied(false);
  }

  function handleCopy() {
    if (!activeResponse) return;
    const text = [
      activeResponse.title,
      "",
      activeResponse.answer,
      "",
      activeResponse.bullets.map((b) => `• ${b}`).join("\n"),
    ].join("\n");
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const isLow = ctx.riskLevel === "low";

  return (
    <section aria-labelledby="section-ask-configtrace" id="ask-configtrace">
      {/* Section header */}
      <h2
        id="section-ask-configtrace"
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          margin: "0 0 8px",
          fontWeight: 500,
        }}
      >
        Ask ConfigTrace
      </h2>

      <div
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "6px",
          padding: "14px 16px",
        }}
      >
        {/* Intro */}
        <p
          style={{
            fontSize: "12px",
            color: "#565b6e",
            margin: "0 0 12px",
            lineHeight: 1.5,
          }}
        >
          Grounded answers based on this change, risk rules, and remediation guidance.
          {isLow && (
            <span style={{ color: "#3a3e50" }}>
              {" "}Fewer questions shown for lower-risk changes.
            </span>
          )}
        </p>

        {/* Question chips */}
        <div
          role="group"
          aria-label="Investigation questions"
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: "6px",
          }}
        >
          {questions.map((q) => (
            <QuestionChip
              key={q.id}
              label={q.label}
              active={activeQuestionId === q.id}
              onClick={() => handleQuestionClick(q.id)}
            />
          ))}
        </div>

        {/* Answer card */}
        {activeResponse && (
          <AnswerCard
            response={activeResponse}
            onCopy={
              activeResponse.question_id === "team_summary"
                ? () => {
                    if (copied) return;
                    handleCopy();
                  }
                : undefined
            }
          />
        )}
      </div>

      {/* Inline keyframe for fade-in (only injected once per render) */}
      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(4px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </section>
  );
}
