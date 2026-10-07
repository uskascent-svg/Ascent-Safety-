import { describe, expect, it } from "vitest";

import { markerSources, routeSources } from "@/lib/globe-data";
import type { EventLocation } from "@/types/api";

function event(overrides: Partial<EventLocation> = {}): EventLocation {
  return {
    id: "event-1",
    latitude: null,
    longitude: null,
    origin_latitude: null,
    origin_longitude: null,
    destination_latitude: null,
    destination_longitude: null,
    country: null,
    region: null,
    threat_type: "phishing",
    severity: "high",
    status: "open",
    source: "test-source",
    title: "Test event",
    occurred_at: "2026-10-07T00:00:00Z",
    ...overrides,
  };
}

describe("backend event projection for the globe", () => {
  it("renders no threat objects when the backend returns no events", () => {
    expect(markerSources([])).toEqual([]);
    expect(routeSources([])).toEqual([]);
  });

  it("renders a reported event coordinate as a marker without inventing a route", () => {
    const rows = [event({ latitude: 40.7, longitude: -74 })];

    expect(markerSources(rows)).toEqual([
      { eventId: "event-1", point: { latitude: 40.7, longitude: -74 }, severity: "high" },
    ]);
    expect(routeSources(rows)).toEqual([]);
  });

  it("renders endpoints and an arc only from explicit origin and destination data", () => {
    const rows = [
      event({
        origin_latitude: 40.7,
        origin_longitude: -74,
        destination_latitude: 51.5,
        destination_longitude: -0.1,
      }),
    ];

    expect(markerSources(rows)).toHaveLength(2);
    expect(routeSources(rows)).toEqual([
      {
        eventId: "event-1",
        severity: "high",
        origin: { latitude: 40.7, longitude: -74 },
        destination: { latitude: 51.5, longitude: -0.1 },
      },
    ]);
  });

  it("does not create an arc from an incomplete route", () => {
    const rows = [event({ origin_latitude: 40.7, origin_longitude: -74 })];

    expect(markerSources(rows)).toHaveLength(1);
    expect(routeSources(rows)).toEqual([]);
  });
});
