"use client";

import SourcesAdmin, { type SourceConfig } from "@/components/SourcesAdmin";

export const SENSORS_CONFIG: SourceConfig = {
  eyebrow: "Network security monitoring",
  title: "Network sensors",
  intro:
    "Register the sources that report network telemetry (for example Zeek or Suricata exports, proxies, or client agents). Findings are based only on what these sensors report; Ascent Safety does not capture traffic itself.",
  noun: "sensor",
  apiBase: "/api/sensors",
  kindField: "kind",
  kindLabel: "Sensor type",
  kinds: [
    { value: "zeek", label: "Zeek" },
    { value: "suricata", label: "Suricata" },
    { value: "proxy", label: "Proxy" },
    { value: "agent", label: "Client agent" },
    { value: "other", label: "Other" },
  ],
  keyHeader: "X-Sensor-Key",
  ingestPath: "/api/network-telemetry",
  emptyHint:
    "Ascent Safety does not include a network sensor, so no network threats can be detected until you connect one using a sensor API key.",
};

export default function SensorsAdmin() {
  return <SourcesAdmin cfg={SENSORS_CONFIG} />;
}
