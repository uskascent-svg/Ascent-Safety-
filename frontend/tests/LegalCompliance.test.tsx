import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import LegalCompliancePage from "@/app/legal-compliance/page";

describe("legal and compliance reference center", () => {
  it("shows the disclaimer and keeps law, guidance, and frameworks distinct", () => {
    render(<LegalCompliancePage />);

    expect(screen.getByRole("heading", { name: "Legal & Compliance" })).toBeInTheDocument();
    expect(screen.getByText(/does not constitute legal advice/i)).toBeInTheDocument();
    expect(screen.getByText("Digital Personal Data Protection Rules, 2025")).toBeInTheDocument();
    expect(screen.getByText("NIST Cybersecurity Framework 2.0")).toBeInTheDocument();
    expect(screen.getByText("PCI Data Security Standard (PCI DSS)")).toBeInTheDocument();
  });

  it("filters references by region and search text", () => {
    render(<LegalCompliancePage />);

    fireEvent.click(screen.getByRole("button", { name: "India" }));
    expect(screen.getByText("Information Technology Act, 2000")).toBeInTheDocument();
    expect(screen.queryByText("General Data Protection Regulation (EU) 2016/679")).not.toBeInTheDocument();

    fireEvent.change(screen.getByRole("searchbox", { name: "Search laws and frameworks" }), {
      target: { value: "DPDP Rules" },
    });
    expect(screen.getByText("Digital Personal Data Protection Rules, 2025")).toBeInTheDocument();
    expect(screen.queryByText("Information Technology Act, 2000")).not.toBeInTheDocument();
  });

  it("links to official primary sources in a separate tab", () => {
    render(<LegalCompliancePage />);
    const link = screen.getAllByRole("link", { name: /India Code · Act text/i })[0];
    expect(link).toHaveAttribute("href", "https://www.indiacode.nic.in/bitstream/123456789/13116/1/it_act_2000_updated.pdf");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });
});
