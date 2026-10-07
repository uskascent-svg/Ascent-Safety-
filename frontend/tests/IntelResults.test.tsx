import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import IntelResults from "@/components/IntelResults";
import type { IntelLookup } from "@/types/api";

const lookup: IntelLookup = {
  indicator: "8.8.4.4",
  indicator_type: "ip",
  verdict: "malicious",
  note: "'clean' means not flagged by the queried services. It is not a guarantee of safety.",
  results: [
    {
      provider: "abuseipdb",
      status: "ok",
      verdict: "malicious",
      cached: false,
      checked_at: null,
      detail: { abuse_confidence_score: 90, total_reports: 12, isp: null },
    },
    {
      provider: "virustotal",
      status: "rate_limited",
      verdict: "unknown",
      cached: false,
      checked_at: null,
      detail: { error: "Provider rate limit reached" },
    },
    {
      provider: "urlhaus",
      status: "not_found",
      verdict: "unknown",
      cached: true,
      checked_at: null,
      detail: {},
    },
  ],
};

describe("IntelResults", () => {
  it("shows per-provider verdicts, details, and honest non-answers", () => {
    render(<IntelResults lookup={lookup} />);
    expect(screen.getAllByText("Malicious")).toHaveLength(2); // overall + AbuseIPDB
    expect(screen.getByText("AbuseIPDB")).toBeInTheDocument();
    expect(screen.getByText(/abuse confidence score: 90/)).toBeInTheDocument();
    expect(screen.getByText("Rate limited")).toBeInTheDocument();
    expect(screen.getByText("No record")).toBeInTheDocument();
    expect(screen.getByText("Cached result")).toBeInTheDocument();
    expect(screen.getByText(/not a guarantee of safety/)).toBeInTheDocument();
  });
});
