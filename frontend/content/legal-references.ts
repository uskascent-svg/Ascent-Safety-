export type LegalCategory = "Indian law" | "Regulatory guidance" | "International regulation" | "Security framework" | "Industry standard" | "Assurance reporting";
export type Jurisdiction = "India" | "European Union" | "United States" | "Global";

export interface LegalReference {
  id: string;
  title: string;
  jurisdiction: Jurisdiction;
  category: LegalCategory;
  authority: string;
  published: string;
  summary: string;
  applicability: string;
  sourceUrl: string;
  sourceLabel: string;
  verifiedAt: string;
  version: string;
  tags: string[];
}

// Version-controlled reference content. Update summaries only after checking the official source.
// This is intentionally separate from page components so it can later move behind a content API.
export const legalReferences: LegalReference[] = [
  {
    id: "it-act-2000",
    title: "Information Technology Act, 2000",
    jurisdiction: "India",
    category: "Indian law",
    authority: "Parliament of India · Ministry of Electronics and Information Technology",
    published: "Enacted 9 June 2000",
    summary:
      "India’s principal statute covering legal recognition of electronic records and transactions, electronic signatures, and specified computer-related offences and contraventions.",
    applicability:
      "Application depends on the conduct, parties, applicable amendments, rules, and facts. Check the current text and relevant subordinate legislation.",
    sourceUrl: "https://www.indiacode.nic.in/bitstream/123456789/13116/1/it_act_2000_updated.pdf",
    sourceLabel: "India Code · Act text",
    verifiedAt: "2026-10-07",
    version: "Act No. 21 of 2000",
    tags: ["cyber offences", "electronic records", "electronic signatures", "India Code"],
  },
  {
    id: "cert-in-directions-2022",
    title: "CERT-In Directions under Section 70B",
    jurisdiction: "India",
    category: "Regulatory guidance",
    authority: "Indian Computer Emergency Response Team (CERT-In) · MeitY",
    published: "28 April 2022",
    summary:
      "Directions on information-security practices, incident prevention, response, and reporting, issued under Section 70B(6) of the Information Technology Act. CERT-In also publishes FAQs and related updates.",
    applicability:
      "The directions identify covered entities and obligations. Applicability, timelines, exceptions, and later updates must be assessed against the official direction and current FAQs.",
    sourceUrl: "https://www.cert-in.org.in/Directions70B.jsp",
    sourceLabel: "CERT-In · Directions and FAQs",
    verifiedAt: "2026-10-07",
    version: "Directions dated 28 April 2022",
    tags: ["incident reporting", "Section 70B", "incident response", "CERT-In"],
  },
  {
    id: "dpdp-act-2023",
    title: "Digital Personal Data Protection Act, 2023",
    jurisdiction: "India",
    category: "Indian law",
    authority: "Parliament of India · Ministry of Electronics and Information Technology",
    published: "11 August 2023",
    summary:
      "Indian legislation concerning processing of digital personal data, including concepts such as Data Principals, Data Fiduciaries, consent, safeguards, and specified rights and duties.",
    applicability:
      "The Act contains scope rules and commencement is notification-dependent. Read it together with the final DPDP Rules, 2025, corrigenda, and the official enforcement timeline; not every provision commenced at the same time.",
    sourceUrl: "https://www.indiacode.nic.in/bitstream/123456789/22037/2/a2023-22.pdf",
    sourceLabel: "India Code · Act text",
    verifiedAt: "2026-10-07",
    version: "Act No. 22 of 2023 · India Code text as on 19 November 2025",
    tags: ["personal data", "privacy", "Data Principal", "Data Fiduciary", "DPDP"],
  },
  {
    id: "dpdp-rules-2025",
    title: "Digital Personal Data Protection Rules, 2025",
    jurisdiction: "India",
    category: "Regulatory guidance",
    authority: "Ministry of Electronics and Information Technology · Government of India",
    published: "13 November 2025",
    summary:
      "Final rules made under the DPDP Act. The notified rules specify phased commencement, with different provisions taking effect on different timelines; MeitY also publishes an enforcement timeline and corrigendum.",
    applicability:
      "Do not infer that every rule is currently in force. Confirm the specific rule’s commencement date, the enforcement timeline, corrigenda, and the organization’s status from MeitY’s official materials.",
    sourceUrl:
      "https://www.meity.gov.in/documents/act-and-policies/digital-personal-data-protection-rules-2025-gDOxUjMtQWa",
    sourceLabel: "MeitY · Rules, corrigendum and timeline",
    verifiedAt: "2026-10-07",
    version: "Final Rules, 2025 · corrigendum listed 16 December 2025",
    tags: ["DPDP Rules", "commencement", "data protection", "MeitY"],
  },
  {
    id: "gdpr",
    title: "General Data Protection Regulation (EU) 2016/679",
    jurisdiction: "European Union",
    category: "International regulation",
    authority: "European Parliament and Council of the European Union",
    published: "27 April 2016 · applicable from 25 May 2018",
    summary:
      "EU regulation on protection of natural persons in relation to personal-data processing and the movement of such data. It sets obligations and rights for processing within its territorial scope.",
    applicability:
      "Territorial and material scope must be assessed under the Regulation for the specific organization and processing. Consult the current consolidated text and applicable supervisory-authority guidance.",
    sourceUrl: "https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng/",
    sourceLabel: "EUR-Lex · Official Journal text",
    verifiedAt: "2026-10-07",
    version: "Regulation (EU) 2016/679",
    tags: ["personal data", "privacy", "data subjects", "EU"],
  },
  {
    id: "nist-csf-2",
    title: "NIST Cybersecurity Framework 2.0",
    jurisdiction: "Global",
    category: "Security framework",
    authority: "National Institute of Standards and Technology (NIST), U.S. Department of Commerce",
    published: "26 February 2024",
    summary:
      "A voluntary risk-management framework providing high-level cybersecurity outcomes. Its six functions are Govern, Identify, Protect, Detect, Respond, and Recover.",
    applicability:
      "Guidance, not a law or certification. Organizations select and tailor outcomes to their context; using this platform does not establish conformity or compliance.",
    sourceUrl: "https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20",
    sourceLabel: "NIST · CSF 2.0 publication",
    verifiedAt: "2026-10-07",
    version: "CSWP 29 · CSF 2.0",
    tags: ["risk management", "Govern", "Identify", "Protect", "Detect", "Respond", "Recover"],
  },
  {
    id: "iso-27001-2022",
    title: "ISO/IEC 27001:2022",
    jurisdiction: "Global",
    category: "Security framework",
    authority: "International Organization for Standardization (ISO) and International Electrotechnical Commission (IEC)",
    published: "October 2022 · Edition 3",
    summary:
      "An international requirements standard for establishing, implementing, maintaining, and continually improving an information security management system (ISMS).",
    applicability:
      "A voluntary international standard unless incorporated into a contract or other applicable requirement. Certification requires a scoped assessment by an appropriate certification body; this platform does not provide certification.",
    sourceUrl: "https://www.iso.org/standard/27001",
    sourceLabel: "ISO · Standard overview",
    verifiedAt: "2026-10-07",
    version: "ISO/IEC 27001:2022 · Edition 3",
    tags: ["ISMS", "risk management", "certification", "international standard"],
  },
  {
    id: "pci-dss",
    title: "PCI Data Security Standard (PCI DSS)",
    jurisdiction: "Global",
    category: "Industry standard",
    authority: "PCI Security Standards Council (PCI SSC)",
    published: "PCI DSS v4.0.1 · June 2024",
    summary:
      "A global industry standard of technical and operational requirements intended to protect payment account data.",
    applicability:
      "Relevant to entities that store, process, or transmit payment account data or can affect the cardholder data environment. Validation requirements depend on payment-brand, acquirer, and contractual arrangements; PCI DSS is not itself a general statute.",
    sourceUrl: "https://www.pcisecuritystandards.org/standards/pci-dss/",
    sourceLabel: "PCI SSC · Standard and documents",
    verifiedAt: "2026-10-07",
    version: "PCI DSS v4.0.1",
    tags: ["payment card", "cardholder data", "payments", "PCI"],
  },
  {
    id: "hipaa-security-rule",
    title: "HIPAA Security Rule",
    jurisdiction: "United States",
    category: "International regulation",
    authority: "U.S. Department of Health and Human Services · Office for Civil Rights",
    published: "Final rule published 20 February 2003 · current rule summary",
    summary:
      "U.S. federal requirements for administrative, physical, and technical safeguards protecting electronic protected health information (ePHI).",
    applicability:
      "Applies to HIPAA covered entities and business associates within the rule’s scope. HHS notes that proposed modifications are not the current rule; review current regulations and official updates before making decisions.",
    sourceUrl: "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html",
    sourceLabel: "HHS · Security Rule summary",
    verifiedAt: "2026-10-07",
    version: "45 CFR Part 160 and Part 164, Subparts A and C",
    tags: ["healthcare", "ePHI", "safeguards", "United States"],
  },
  {
    id: "soc-2",
    title: "SOC 2 examination and reporting",
    jurisdiction: "Global",
    category: "Assurance reporting",
    authority: "American Institute of Certified Public Accountants (AICPA)",
    published: "Trust Services Criteria: 2017, revised points of focus 2022",
    summary:
      "An independent CPA examination and report on a service organization’s controls relevant to security, availability, processing integrity, confidentiality, or privacy.",
    applicability:
      "SOC 2 is an assurance engagement/reporting framework, not a law or a certification issued by this application. A report is performed by an independent CPA under applicable professional standards and a defined scope.",
    sourceUrl: "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
    sourceLabel: "AICPA · SOC resources",
    verifiedAt: "2026-10-07",
    version: "SOC 2 · AICPA Trust Services Criteria",
    tags: ["assurance", "service organization", "Trust Services Criteria", "audit"],
  },
];

export const legalDisclaimer =
  "This platform provides cybersecurity information and compliance references for educational and operational awareness purposes. It does not constitute legal advice. Applicability of any law, regulation, standard, reporting obligation, deadline, or penalty depends on the organization, jurisdiction, sector, facts, and current law. Consult qualified legal counsel or the relevant authority for legal decisions.";
