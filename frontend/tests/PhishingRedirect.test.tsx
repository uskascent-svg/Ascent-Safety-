import { describe, expect, it, vi } from "vitest";

const { redirect } = vi.hoisted(() => ({ redirect: vi.fn() }));
vi.mock("next/navigation", () => ({ redirect }));

import PhishingPage from "@/app/phishing/page";

describe("retired phishing route", () => {
  it("redirects old bookmarks to Threat Analyzer", () => {
    PhishingPage();
    expect(redirect).toHaveBeenCalledWith("/threat-analyzer");
  });
});
