"use client";

import * as maplibregl from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import { useEffect, useRef, useState } from "react";

import { SEVERITY_META } from "@/lib/labels";
import type { EventLocation } from "@/types/api";

// Base map only (no threat data). Swap via env for self-hosted tiles in production.
const STYLE_URL =
  process.env.NEXT_PUBLIC_MAP_STYLE_URL?.trim() ||
  "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json";

const SOURCE = "events";

function fitToEvents(map: maplibregl.Map, events: EventLocation[]) {
  const bounds = new maplibregl.LngLatBounds();
  let hasCoordinates = false;
  for (const event of events) {
    for (const [latitude, longitude] of [
      [event.latitude, event.longitude],
      [event.origin_latitude, event.origin_longitude],
      [event.destination_latitude, event.destination_longitude],
    ]) {
      if (latitude == null || longitude == null) continue;
      bounds.extend([longitude, latitude]);
      hasCoordinates = true;
    }
  }
  if (hasCoordinates) map.fitBounds(bounds, { padding: 84, maxZoom: 3.4, duration: 0 });
}

function toGeoJson(events: EventLocation[]): GeoJSON.FeatureCollection<GeoJSON.Geometry> {
  const features: GeoJSON.Feature<GeoJSON.Geometry>[] = [];
  for (const event of events) {
    const properties = { id: event.id, severity: event.severity, title: event.title };
    const hasRoute = event.origin_latitude != null && event.origin_longitude != null
      && event.destination_latitude != null && event.destination_longitude != null;

    if (hasRoute) {
      const origin: [number, number] = [event.origin_longitude!, event.origin_latitude!];
      const destination: [number, number] = [event.destination_longitude!, event.destination_latitude!];
      features.push({
        type: "Feature",
        geometry: { type: "LineString", coordinates: [origin, destination] },
        properties: { ...properties, kind: "route" },
      });
      features.push(
        { type: "Feature", geometry: { type: "Point", coordinates: origin }, properties: { ...properties, kind: "origin" } },
        { type: "Feature", geometry: { type: "Point", coordinates: destination }, properties: { ...properties, kind: "destination" } },
      );
    }

    if (event.latitude != null && event.longitude != null) {
      features.push({
        type: "Feature",
        geometry: { type: "Point", coordinates: [event.longitude, event.latitude] },
        properties: { ...properties, kind: "location" },
      });
    }
  }
  return {
    type: "FeatureCollection",
    features,
  };
}

const colorByTable = (): maplibregl.ExpressionSpecification => [
  "match",
  ["get", "severity"],
  "critical",
  SEVERITY_META.critical.hex,
  "high",
  SEVERITY_META.high.hex,
  "medium",
  SEVERITY_META.medium.hex,
  "low",
  SEVERITY_META.low.hex,
  SEVERITY_META.info.hex,
];

// Radius also encodes severity so it is not conveyed by color alone.
const radiusByTable: maplibregl.ExpressionSpecification = [
  "match",
  ["get", "severity"],
  "critical",
  10,
  "high",
  8,
  "medium",
  7,
  "low",
  6,
  5,
];

interface Props {
  events: EventLocation[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  displayMode?: "markers" | "heatmap";
}

export default function ThreatMap({ events, selectedId, onSelect, displayMode = "markers" }: Props) {
  const container = useRef<HTMLDivElement>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const ready = useRef(false);
  const framedEvents = useRef(false);
  const latest = useRef({ events, selectedId, onSelect, displayMode });
  const [mapError, setMapError] = useState<string | null>(null);

  useEffect(() => {
    latest.current = { events, selectedId, onSelect, displayMode };
  }, [events, selectedId, onSelect, displayMode]);

  useEffect(() => {
    if (!container.current) return;
    // MapLibre's default worker URL is emitted as a bundler-specific worker import.
    // Serve the package worker as a regular asset so it works in Next's production build.
    maplibregl.setWorkerUrl(new URL("/maplibre-gl-worker.mjs", window.location.href).toString());
    let map: maplibregl.Map;
    try {
      map = new maplibregl.Map({
        container: container.current,
        style: STYLE_URL,
        center: [10, 25],
        zoom: 1.4,
        minZoom: 1,
        attributionControl: { compact: true },
      });
    } catch {
      queueMicrotask(() => {
        setMapError("The map is unavailable on this device. Use the recent events list instead.");
      });
      return;
    }
    mapRef.current = map;
    map.addControl(new maplibregl.NavigationControl({ showCompass: false }), "top-right");
    const popup = new maplibregl.Popup({ closeButton: false, closeOnClick: false, offset: 12 });

    map.on("error", (event) => {
      if (!ready.current && event.error && mapRef.current === map) {
        map.remove();
        mapRef.current = null;
        setMapError("The map could not load its configured style. Recent events remain available.");
      }
    });
    map.on("load", () => {
      map.addSource(SOURCE, { type: "geojson", data: toGeoJson(latest.current.events) });
      map.addLayer({
        id: "event-heatmap",
        type: "heatmap",
        source: SOURCE,
        maxzoom: 8,
        layout: { visibility: latest.current.displayMode === "heatmap" ? "visible" : "none" },
        paint: {
          "heatmap-weight": ["match", ["get", "severity"], "critical", 1, "high", 0.8, "medium", 0.55, "low", 0.3, 0.15],
          "heatmap-intensity": ["interpolate", ["linear"], ["zoom"], 0, 0.7, 8, 1.4],
          "heatmap-radius": ["interpolate", ["linear"], ["zoom"], 0, 12, 8, 30],
          "heatmap-opacity": ["interpolate", ["linear"], ["zoom"], 6, 0.85, 8, 0.45],
          "heatmap-color": [
            "interpolate", ["linear"], ["heatmap-density"],
            0, "rgba(0,217,255,0)", 0.2, "rgba(0,217,255,0.35)",
            0.45, "rgba(59,130,246,0.58)", 0.7, "rgba(245,158,11,0.72)", 1, "rgba(239,68,68,0.85)",
          ],
        },
      });
      map.addLayer({
        id: "event-routes",
        type: "line",
        source: SOURCE,
        filter: ["==", ["geometry-type"], "LineString"],
        paint: {
          "line-color": colorByTable(),
          "line-width": ["interpolate", ["linear"], ["zoom"], 1, 3, 5, 5],
          "line-opacity": 0.98,
          "line-blur": 0.2,
        },
      });
      map.addLayer({
        id: "event-points",
        type: "circle",
        source: SOURCE,
        filter: ["==", ["geometry-type"], "Point"],
        paint: {
          "circle-color": colorByTable(),
          "circle-radius": ["case", ["==", ["get", "kind"], "origin"], 7, ["==", ["get", "kind"], "destination"], 10, radiusByTable],
          "circle-opacity": 1,
          "circle-stroke-width": 2,
          "circle-stroke-color": "#f8fafc",
        },
      });
      map.addLayer({
        id: "event-selected-route",
        type: "line",
        source: SOURCE,
        filter: ["all", ["==", ["get", "id"], latest.current.selectedId ?? ""], ["==", ["geometry-type"], "LineString"]],
        paint: {
          "line-color": "#ffffff",
          "line-width": 4,
          "line-opacity": 0.95,
          "line-blur": 1,
        },
      });
      map.addLayer({
        id: "event-selected",
        type: "circle",
        source: SOURCE,
        filter: ["all", ["==", ["get", "id"], latest.current.selectedId ?? ""], ["==", ["geometry-type"], "Point"]],
        paint: {
          "circle-color": "rgba(0,0,0,0)",
          "circle-radius": 16,
          "circle-stroke-width": 2,
          "circle-stroke-color": "#ffffff",
        },
      });
      map.setLayoutProperty("event-points", "visibility", latest.current.displayMode === "markers" ? "visible" : "none");
      map.setLayoutProperty("event-selected", "visibility", latest.current.displayMode === "markers" ? "visible" : "none");

      const selectFeature = (e: maplibregl.MapLayerMouseEvent) => {
        const id = e.features?.[0]?.properties?.id as string | undefined;
        if (id) latest.current.onSelect(id);
      };
      map.on("click", "event-points", selectFeature);
      map.on("click", "event-routes", selectFeature);
      map.on("mouseenter", "event-points", (e) => {
        map.getCanvas().style.cursor = "pointer";
        const f = e.features?.[0];
        if (!f || f.geometry.type !== "Point") return;
        const sev = SEVERITY_META[f.properties?.severity as keyof typeof SEVERITY_META];
        // setText (not setHTML): event titles come from external telemetry and must stay inert.
        popup
          .setLngLat(f.geometry.coordinates as [number, number])
          .setText(`${sev?.label ?? ""}: ${String(f.properties?.title ?? "")}`)
          .addTo(map);
      });
      map.on("mouseleave", "event-points", () => {
        map.getCanvas().style.cursor = "";
        popup.remove();
      });
      map.on("mouseenter", "event-routes", () => { map.getCanvas().style.cursor = "pointer"; });
      map.on("mouseleave", "event-routes", () => { map.getCanvas().style.cursor = ""; popup.remove(); });
      map.on("mousemove", "event-routes", (e) => {
        const feature = e.features?.[0];
        if (!feature) return;
        const severity = SEVERITY_META[feature.properties?.severity as keyof typeof SEVERITY_META];
        popup.setLngLat(e.lngLat).setText(`${severity?.label ?? ""}: ${String(feature.properties?.title ?? "")}`).addTo(map);
      });
      fitToEvents(map, latest.current.events);
      framedEvents.current = latest.current.events.some((event) =>
        event.latitude != null || event.origin_latitude != null || event.destination_latitude != null,
      );
      ready.current = true;
    });

    return () => {
      ready.current = false;
      popup.remove();
      map.remove();
      mapRef.current = null;
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || !ready.current) return;
    (map.getSource(SOURCE) as maplibregl.GeoJSONSource | undefined)?.setData(toGeoJson(events));
    if (!framedEvents.current && events.length > 0) {
      fitToEvents(map, events);
      framedEvents.current = events.some((event) =>
        event.latitude != null || event.origin_latitude != null || event.destination_latitude != null,
      );
    }
  }, [events]);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || !ready.current) return;
    const markersVisible = displayMode === "markers" ? "visible" : "none";
    map.setLayoutProperty("event-heatmap", "visibility", displayMode === "heatmap" ? "visible" : "none");
    map.setLayoutProperty("event-points", "visibility", markersVisible);
    map.setLayoutProperty("event-selected", "visibility", markersVisible);
    map.setLayoutProperty("event-routes", "visibility", "visible");
    map.setLayoutProperty("event-selected-route", "visibility", "visible");
  }, [displayMode]);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || !ready.current) return;
    map.setFilter("event-selected", ["==", ["get", "id"], selectedId ?? ""]);
    map.setFilter("event-selected-route", ["all", ["==", ["get", "id"], selectedId ?? ""], ["==", ["geometry-type"], "LineString"]]);
    const sel = events.find((e) => e.id === selectedId);
    if (sel?.latitude != null && sel.longitude != null) {
      map.easeTo({ center: [sel.longitude, sel.latitude], zoom: Math.max(map.getZoom(), 3.5) });
    } else if (sel?.origin_latitude != null && sel.origin_longitude != null && sel.destination_latitude != null && sel.destination_longitude != null) {
      map.fitBounds(
        [[sel.origin_longitude, sel.origin_latitude], [sel.destination_longitude, sel.destination_latitude]],
        { padding: 64, maxZoom: 4.5, duration: 700 },
      );
    }
  }, [events, selectedId]);

  if (mapError) {
    return (
      <div className="grid h-full place-items-center px-6 text-center" role="status">
        <p className="max-w-md text-sm text-slate-300">{mapError}</p>
      </div>
    );
  }

  return (
    <div
      ref={container}
      role="region"
      aria-label="World map of security events. The event list shows the same events in text form."
      className="h-full w-full"
    />
  );
}
