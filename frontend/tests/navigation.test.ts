import { describe, expect, it } from "vitest";

import { navigationItemAllowed, WORKSPACE_NAVIGATION } from "@/lib/navigation";

describe("workspace navigation", () => {
  it("contains the nine intended panels without the retired phishing lab or sensors", () => {
    expect(WORKSPACE_NAVIGATION.map((item) => item.href)).toEqual([
      "/",
      "/security-panel",
      "/reports",
      "/case-studies",
      "/legal-compliance",
      "/guidance",
      "/threat-analyzer",
      "/endpoints",
      "/threat-network",
    ]);
    expect(WORKSPACE_NAVIGATION.some((item) => item.href === "/phishing" || item.href === "/sensors")).toBe(false);
  });

  it("filters operations links by the caller's verified capabilities", () => {
    const workspaceUser = { authenticated: true, canViewPanel: false, canAccessThreatNetwork: false };
    const analyst = { ...workspaceUser, canViewPanel: true };
    const modelMonitor = { ...workspaceUser, canAccessThreatNetwork: true };

    expect(WORKSPACE_NAVIGATION.filter((item) => navigationItemAllowed(item, workspaceUser)).map((item) => item.href))
      .not.toContain("/security-panel");
    expect(WORKSPACE_NAVIGATION.filter((item) => navigationItemAllowed(item, analyst)).map((item) => item.href))
      .toContain("/endpoints");
    expect(WORKSPACE_NAVIGATION.filter((item) => navigationItemAllowed(item, modelMonitor)).map((item) => item.href))
      .toContain("/threat-network");
  });
});
