import { AlertCircle, AlertTriangle, Info, ShieldAlert, type LucideIcon } from "lucide-react";

import { SEVERITY_META } from "@/lib/labels";
import type { Severity } from "@/types/api";

// Icon + text label, so severity never depends on color alone.
const ICONS: Record<Severity, LucideIcon> = {
  critical: ShieldAlert,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
  info: Info,
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  const meta = SEVERITY_META[severity];
  const Icon = ICONS[severity];
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-xs font-medium ${meta.classes}`}
    >
      <Icon className="h-3 w-3" aria-hidden="true" />
      {meta.label}
    </span>
  );
}
