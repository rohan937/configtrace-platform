/**
 * timing.ts — single source of truth for the video's tempo (v2 rebuild).
 *
 * "Know what changed. Know what is risky. Know what needs review." — a 9-scene,
 * fully mock-UI walkthrough of ConfigTrace's configuration security + drift
 * intelligence platform, covering all 20 providers through Terraform Cloud.
 *
 * Edit scene durations here; total length is derived automatically.
 * All values are in FRAMES.
 */

export const FPS = 30;
export const WIDTH = 1920;
export const HEIGHT = 1080;

const sec = (s: number) => Math.round(s * FPS);

/** Ordered list of scenes with their durations (80s total). */
export const SCENES = [
  { id: "hook", durationInFrames: sec(6) }, //           0:00 - 0:06  Code is not the only thing that changes
  { id: "controlPlane", durationInFrames: sec(7) }, //   0:06 - 0:13  The hidden control plane (provider grid)
  { id: "snapshot", durationInFrames: sec(9) }, //       0:13 - 0:22  Configuration snapshot engine
  { id: "drift", durationInFrames: sec(9) }, //          0:22 - 0:31  Drift detection (diff panel + cursor)
  { id: "risk", durationInFrames: sec(11) }, //          0:31 - 0:42  Risk classification (findings board + cursor)
  { id: "activity", durationInFrames: sec(11) }, //      0:42 - 0:53  Activity evidence (timeline + cursor)
  { id: "caseGraph", durationInFrames: sec(11) }, //     0:53 - 1:04  Case graph + report (cursor)
  { id: "commandCenter", durationInFrames: sec(9) }, //  1:04 - 1:13  Cross-provider command center + coverage matrix
  { id: "finale", durationInFrames: sec(7) }, //         1:13 - 1:20  Final positioning + system map
] as const;

export type SceneId = (typeof SCENES)[number]["id"];

/** Absolute start frame of each scene, derived from the durations above. */
export const SCENE_OFFSETS: Record<string, number> = (() => {
  const offsets: Record<string, number> = {};
  let cursor = 0;
  for (const s of SCENES) {
    offsets[s.id] = cursor;
    cursor += s.durationInFrames;
  }
  return offsets;
})();

/** Total composition length in frames (80s @ 30fps = 2400). */
export const TOTAL_DURATION = SCENES.reduce(
  (acc, s) => acc + s.durationInFrames,
  0,
);

export const sceneFrames = (id: SceneId): number =>
  SCENES.find((s) => s.id === id)!.durationInFrames;
