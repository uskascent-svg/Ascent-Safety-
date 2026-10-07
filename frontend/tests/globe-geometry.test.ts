import { describe, expect, it } from "vitest";

import { geographicToVector3, greatCirclePoints } from "@/lib/globe-geometry";

describe("globe geometry", () => {
  it("maps the equator, prime meridian, and poles to the expected sphere axes", () => {
    const primeMeridian = geographicToVector3({ latitude: 0, longitude: 0 });
    expect(primeMeridian.x).toBeCloseTo(1);
    expect(primeMeridian.y).toBeCloseTo(0);
    expect(primeMeridian.z).toBeCloseTo(0);
    expect(geographicToVector3({ latitude: 90, longitude: 0 }).y).toBeCloseTo(1);
    expect(geographicToVector3({ latitude: -90, longitude: 0 }).y).toBeCloseTo(-1);
    expect(geographicToVector3({ latitude: 0, longitude: 90 }).z).toBeCloseTo(-1);
  });

  it("rejects invalid geographic values and radii", () => {
    expect(() => geographicToVector3({ latitude: 91, longitude: 0 })).toThrow(RangeError);
    expect(() => geographicToVector3({ latitude: 0, longitude: 181 })).toThrow(RangeError);
    expect(() => geographicToVector3({ latitude: 0, longitude: 0 }, 0)).toThrow(RangeError);
  });

  it("builds a curved route with exact endpoints and an elevated midpoint", () => {
    const route = greatCirclePoints(
      { latitude: 0, longitude: 0 },
      { latitude: 0, longitude: 90 },
      16,
    );

    expect(route).toHaveLength(17);
    expect(route[0].distanceTo(geographicToVector3({ latitude: 0, longitude: 0 }))).toBeCloseTo(0);
    expect(route.at(-1)?.distanceTo(geographicToVector3({ latitude: 0, longitude: 90 }))).toBeCloseTo(
      0,
    );
    expect(route[8].length()).toBeGreaterThan(1);
  });

  it("handles antipodal coordinates without producing invalid points", () => {
    const route = greatCirclePoints(
      { latitude: 0, longitude: 0 },
      { latitude: 0, longitude: 180 },
      8,
    );

    expect(route).toHaveLength(9);
    expect(route.every((point) => Number.isFinite(point.x + point.y + point.z))).toBe(true);
  });
});
