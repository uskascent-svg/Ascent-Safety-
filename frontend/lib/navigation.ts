import {
  Activity,
  BookOpen,
  Compass,
  FilePlus2,
  LayoutDashboard,
  LockKeyhole,
  ScrollText,
  Shield,
  type LucideIcon,
} from "lucide-react";

export type NavigationPermission = "workspace" | "authenticated" | "security-operations" | "threat-network";

export type NavigationItem = {
  href: string;
  label: string;
  description: string;
  group: "Workspace" | "Operations";
  icon: LucideIcon;
  requiredPermission: NavigationPermission;
  featureFlag?: string;
};

export const WORKSPACE_NAVIGATION: readonly NavigationItem[] = [
  { href: "/", label: "Overview", description: "Workspace landing page", group: "Workspace", icon: LayoutDashboard, requiredPermission: "workspace" },
  { href: "/security-panel", label: "Security", description: "Security events and alerts", group: "Operations", icon: Shield, requiredPermission: "security-operations" },
  { href: "/reports", label: "Report issue", description: "Submit and track a security report", group: "Workspace", icon: FilePlus2, requiredPermission: "workspace" },
  { href: "/case-studies", label: "Case studies", description: "Resolved security incidents", group: "Workspace", icon: BookOpen, requiredPermission: "workspace" },
  { href: "/legal-compliance", label: "Legal & compliance", description: "Cybersecurity reference library", group: "Workspace", icon: ScrollText, requiredPermission: "workspace" },
  { href: "/guidance", label: "Guidance assistant", description: "Defensive security and product guidance", group: "Workspace", icon: Compass, requiredPermission: "workspace" },
  { href: "/threat-analyzer", label: "Threat analyzer", description: "Analyze suspicious text, URLs, and files", group: "Workspace", icon: Shield, requiredPermission: "workspace" },
  { href: "/endpoints", label: "Defense center", description: "Endpoint telemetry and response monitoring", group: "Operations", icon: LockKeyhole, requiredPermission: "security-operations" },
  { href: "/threat-network", label: "Threat detection network", description: "Threat analysis metrics and model operations", group: "Operations", icon: Activity, requiredPermission: "threat-network" },
];

export function navigationItemAllowed(
  item: NavigationItem,
  permissions: { authenticated: boolean; canViewPanel: boolean; canAccessThreatNetwork: boolean },
) {
  switch (item.requiredPermission) {
    case "workspace": return true;
    case "authenticated": return permissions.authenticated;
    case "security-operations": return permissions.canViewPanel;
    case "threat-network": return permissions.canAccessThreatNetwork;
  }
}
