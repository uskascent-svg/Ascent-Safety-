"use client";

import SourcesAdmin, { type SourceConfig } from "@/components/SourcesAdmin";

export const ENDPOINTS_CONFIG: SourceConfig = {
  eyebrow: "Malware & ransomware monitoring",
  title: "Endpoints",
  intro:
    "Register the sources that report endpoint telemetry. Detections are based only on behaviour those agents report; nothing is executed or quarantined by Ascent Safety.",
  noun: "endpoint",
  apiBase: "/api/endpoints",
  kindField: "os",
  kindLabel: "Operating system",
  kinds: [
    { value: "windows", label: "Windows" },
    { value: "linux", label: "Linux" },
    { value: "macos", label: "macOS" },
  ],
  keyHeader: "X-Endpoint-Key",
  ingestPath: "/api/endpoint-telemetry",
  emptyHint:
    "Ascent Safety does not include an endpoint agent. It receives telemetry from agents you connect using an endpoint API key.",
};

export default function EndpointsAdmin() {
  return <SourcesAdmin cfg={ENDPOINTS_CONFIG} />;
}
