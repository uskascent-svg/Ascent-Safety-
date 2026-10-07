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

function toGeoJson(events: EventLocation[]): GeoJSON.FeatureCollection<GeoJSON.Point> {
  const pointEvents = events.filter(
    (event): event is EventLocation & { latitude: number; longitude: number } =>
      event.latitude !== null && event.longitude !== null,
  );
  return {
    type: "FeatureCollection",
    features: pointEvents.map((e) => ({
      type: "Feature",
      geometry: { type: "Point", coordinates: [e.longitude, e.latitude] },
      properties: { id: e.id, severity: e.severity, title: e.title },
    })),
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
  const latest = useRef({ events, selectedId, onSelect, displayMode });
  const [mapError, setMapError] = useState<string | null>(null);

  useEffect(() => {
    latest.current = { events, selectedId, onSelect, displayMode };
  }, [events, selectedId, onSelect, displayMode]);

  useEffect(() => {
    if (!container.current) return;
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
        id: "event-points",
        type: "circle",
        source: SOURCE,
        paint: {
          "circle-color": colorByTable(),
          "circle-radius": radiusByTable,
          "circle-opacity": 0.85,
          "circle-stroke-width": 1.5,
          "circle-stroke-color": "#0b1220",
        },
      });
      map.addLayer({
        id: "event-selected",
        type: "circle",
        source: SOURCE,
        filter: ["==", ["get", "id"], latest.current.selectedId ?? ""],
        paint: {
          "circle-color": "rgba(0,0,0,0)",
          "circle-radius": 16,
          "circle-stroke-width": 2,
          "circle-stroke-color": "#ffffff",
        },
      });
      map.setLayoutProperty("event-points", "visibility", latest.current.displayMode === "markers" ? "visible" : "none");
      map.setLayoutProperty("event-selected", "visibility", latest.current.displayMode === "markers" ? "visible" : "none");

      map.on("click", "event-points", (e) => {
        const id = e.features?.[0]?.properties?.id as string | undefined;
        if (id) latest.current.onSelect(id);
      });
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
  }, [events]);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || !ready.current) return;
    const markersVisible = displayMode === "markers" ? "visible" : "none";
    map.setLayoutProperty("event-heatmap", "visibility", displayMode === "heatmap" ? "visible" : "none");
    map.setLayoutProperty("event-points", "visibility", markersVisible);
    map.setLayoutProperty("event-selected", "visibility", markersVisible);
  }, [displayMode]);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || !ready.current) return;
    map.setFilter("event-selected", ["==", ["get", "id"], selectedId ?? ""]);
    const sel = events.find((e) => e.id === selectedId);
    if (sel?.latitude != null && sel.longitude != null) {
      map.easeTo({ center: [sel.longitude, sel.latitude], zoom: Math.max(map.getZoom(), 3.5) });
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
