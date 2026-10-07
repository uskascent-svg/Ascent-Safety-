import { describe, expect, it } from "vitest";

import { defaultFilters, toParams } from "@/lib/filters";

describe("toParams", () => {
  const now = Date.UTC(2026, 9, 6, 12, 0, 0);

  it("sends only the filters that are set", () => {
    const p = toParams({ ...defaultFilters, range: "all" }, now);
    expect(p.toString()).toBe("");
  });

  it("repeats multi-value params and computes since from the range", () => {
    const p = toParams(
      {
        ...defaultFilters,
        severity: ["critical", "high"],
        region: "EMEA",
        q: " login ",
        range: "1h",
      },
      now,
    );
    expect(p.getAll("severity")).toEqual(["critical", "high"]);
    expect(p.get("region")).toBe("EMEA");
    expect(p.get("q")).toBe("login");
    expect(p.get("since")).toBe("2026-10-06T11:00:00.000Z");
  });
});
