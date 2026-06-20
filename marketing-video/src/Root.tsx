import React from "react";
import { Composition } from "remotion";
import { ConfigTraceWalkthroughV2 } from "./ConfigTraceWalkthroughV2";
import { FPS, HEIGHT, TOTAL_DURATION, WIDTH } from "./timing";

export const RemotionRoot: React.FC = () => {
  return (
    <Composition
      id="ConfigTraceSecurityExposureWalkthroughV2"
      component={ConfigTraceWalkthroughV2}
      durationInFrames={TOTAL_DURATION}
      fps={FPS}
      width={WIDTH}
      height={HEIGHT}
    />
  );
};
