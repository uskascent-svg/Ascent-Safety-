import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import ThreatMap from "@/components/ThreatMap";

vi.mock("maplibre-gl", () => ({
  Map: class {
    constructor() {
      throw new Error("WebGL is not supported");
    }
  },
}));

describe("ThreatMap", () => {
  it("keeps the event list usable when the interactive map cannot initialize", async () => {
    render(<ThreatMap events={[]} selectedId={null} onSelect={() => {}} />);

    expect(
      await screen.findByText("The map is unavailable on this device. Use the recent events list instead."),
    ).toBeInTheDocument();
  });
});
