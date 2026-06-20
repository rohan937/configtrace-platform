import React from "react";
import { AbsoluteFill, Sequence } from "remotion";
import { SCENE_OFFSETS, sceneFrames } from "./timing";
import {
  HookScene,
  ControlPlaneScene,
  SnapshotScene,
  DriftScene,
  RiskScene,
  ActivityScene,
  CaseGraphScene,
  CommandCenterScene,
  FinaleScene,
} from "./ScenesV2";

/**
 * ConfigTraceWalkthroughV2 — "Know what changed. Know what is risky.
 * Know what needs review."
 *
 * A 9-scene, fully mock-UI walkthrough of ConfigTrace's configuration security
 * + drift intelligence platform: control plane → snapshot → drift → risk →
 * activity → case → command center → positioning. All 20 providers covered
 * through Terraform Cloud.
 *
 * No screenshots, no network, no external images — everything is animated
 * mock UI, provider chips, graph panels, dashboards, timelines, and motion.
 */
export const ConfigTraceWalkthroughV2: React.FC = () => {
  return (
    <AbsoluteFill style={{ background: "#080B10" }}>
      <Sequence from={SCENE_OFFSETS.hook} durationInFrames={sceneFrames("hook")}>
        <HookScene />
      </Sequence>
      <Sequence from={SCENE_OFFSETS.controlPlane} durationInFrames={sceneFrames("controlPlane")}>
        <ControlPlaneScene />
      </Sequence>
      <Sequence from={SCENE_OFFSETS.snapshot} durationInFrames={sceneFrames("snapshot")}>
        <SnapshotScene />
      </Sequence>
      <Sequence from={SCENE_OFFSETS.drift} durationInFrames={sceneFrames("drift")}>
        <DriftScene />
      </Sequence>
      <Sequence from={SCENE_OFFSETS.risk} durationInFrames={sceneFrames("risk")}>
        <RiskScene />
      </Sequence>
      <Sequence from={SCENE_OFFSETS.activity} durationInFrames={sceneFrames("activity")}>
        <ActivityScene />
      </Sequence>
      <Sequence from={SCENE_OFFSETS.caseGraph} durationInFrames={sceneFrames("caseGraph")}>
        <CaseGraphScene />
      </Sequence>
      <Sequence from={SCENE_OFFSETS.commandCenter} durationInFrames={sceneFrames("commandCenter")}>
        <CommandCenterScene />
      </Sequence>
      <Sequence from={SCENE_OFFSETS.finale} durationInFrames={sceneFrames("finale")}>
        <FinaleScene />
      </Sequence>
    </AbsoluteFill>
  );
};
