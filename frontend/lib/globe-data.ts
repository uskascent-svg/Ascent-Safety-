import type { EventLocation } from "@/types/api";
import type { GeoPoint } from "@/lib/globe-geometry";

export interface MarkerSource {
  eventId: string;
  point: GeoPoint;
  severity: EventLocation["severity"];
}

export interface RouteSource {
  eventId: string;
  origin: GeoPoint;
  destination: GeoPoint;
  severity: EventLocation["severity"];
}

/** Project only coordinates explicitly reported by an event; never synthesize a threat marker. */
export function markerSources(events: EventLocation[]): MarkerSource[] {
  return events.flatMap((event) => {
    const points: GeoPoint[] = [];
    if (event.latitude !== null && event.longitude !== null) {
      points.push({ latitude: event.latitude, longitude: event.longitude });
    }
    if (event.origin_latitude !== null && event.origin_longitude !== null) {
      points.push({ latitude: event.origin_latitude, longitude: event.origin_longitude });
    }
    if (event.destination_latitude !== null && event.destination_longitude !== null) {
      points.push({ latitude: event.destination_latitude, longitude: event.destination_longitude });
    }
    return points.map((point) => ({ eventId: event.id, point, severity: event.severity }));
  });
}

/** Emit a route only when the event supplies both complete geographic endpoint pairs. */
export function routeSources(events: EventLocation[]): RouteSource[] {
  return events.flatMap((event) => {
    if (
      event.origin_latitude === null ||
      event.origin_longitude === null ||
      event.destination_latitude === null ||
      event.destination_longitude === null
    ) {
      return [];
    }
    return [
      {
        eventId: event.id,
        severity: event.severity,
        origin: { latitude: event.origin_latitude, longitude: event.origin_longitude },
        destination: {
          latitude: event.destination_latitude,
          longitude: event.destination_longitude,
        },
      },
    ];
  });
}
