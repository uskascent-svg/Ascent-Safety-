"use client";

import { useMemo, useState } from "react";
import { ArrowUpRight, BookOpenCheck, CalendarClock, FileSearch, Scale, Search } from "lucide-react";

import { legalDisclaimer, legalReferences, type LegalCategory } from "@/content/legal-references";

type RegionFilter = "All regions" | "India" | "European Union" | "United States" | "Global";
type CategoryFilter = "All references" | LegalCategory;

const regions: RegionFilter[] = ["All regions", "India", "European Union", "United States", "Global"];
const categories: CategoryFilter[] = ["All references", "Indian law", "Regulatory guidance", "International regulation", "Security framework", "Industry standard", "Assurance reporting"];

const categoryTone: Record<LegalCategory, string> = {
  "Indian law": "border-cyan-300/20 bg-cyan-300/[0.07] text-cyan-100",
  "Regulatory guidance": "border-amber-300/20 bg-amber-300/[0.07] text-amber-100",
  "International regulation": "border-blue-300/20 bg-blue-300/[0.07] text-blue-100",
  "Security framework": "border-emerald-300/20 bg-emerald-300/[0.07] text-emerald-100",
  "Industry standard": "border-violet-300/20 bg-violet-300/[0.07] text-violet-100",
  "Assurance reporting": "border-slate-300/20 bg-slate-300/[0.06] text-slate-200",
};

export default function LegalCompliancePage() {
  const [query, setQuery] = useState("");
  const [region, setRegion] = useState<RegionFilter>("All regions");
  const [category, setCategory] = useState<CategoryFilter>("All references");

  const references = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase();
    return legalReferences.filter((item) => {
      const regionMatches = region === "All regions" || item.jurisdiction === region;
      const categoryMatches = category === "All references" || item.category === category;
      const searchable = [item.title, item.jurisdiction, item.category, item.authority, item.summary, item.applicability, ...item.tags]
        .join(" ")
        .toLocaleLowerCase();
      return regionMatches && categoryMatches && (!normalized || searchable.includes(normalized));
    });
  }, [category, query, region]);

  return (
    <div className="mx-auto max-w-[1440px] px-4 py-8 sm:px-6 lg:px-10 lg:py-11">
      <section className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-[radial-gradient(ellipse_at_80%_0%,rgba(0,217,255,0.12),transparent_42%),linear-gradient(130deg,#0b1420,#080b13_58%,#0b1020)] p-6 sm:p-9">
        <div className="pointer-events-none absolute -right-20 -top-28 h-80 w-80 rounded-full border border-cyan-100/[0.06]" />
        <div className="pointer-events-none absolute -right-8 -top-16 h-56 w-56 rounded-full border border-cyan-100/[0.05]" />
        <div className="relative max-w-3xl">
          <div className="eyebrow flex items-center gap-2"><Scale className="h-3.5 w-3.5" aria-hidden="true" /> Reference library · verified sources</div>
          <h1 className="mt-4 text-3xl font-semibold tracking-[-0.04em] text-white sm:text-4xl">Legal &amp; Compliance</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-300 sm:text-base">
            An India-first guide to cybersecurity law, incident guidance, privacy rules and risk frameworks, with primary-source links and clear scope notes.
          </p>
          <div className="mt-6 flex flex-wrap gap-x-5 gap-y-2 text-[11px] text-slate-400">
            <span className="inline-flex items-center gap-2"><BookOpenCheck className="h-3.5 w-3.5 text-accent-strong" aria-hidden="true" /> {legalReferences.length} official references</span>
            <span className="inline-flex items-center gap-2"><CalendarClock className="h-3.5 w-3.5 text-accent-strong" aria-hidden="true" /> Sources checked 7 Oct 2026</span>
          </div>
        </div>
      </section>

      <section className="mt-5 rounded-xl border border-amber-300/20 bg-amber-300/[0.055] p-4 sm:p-5" aria-labelledby="legal-notice-title">
        <div className="flex gap-3">
          <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-amber-200/20 bg-amber-200/[0.08] text-amber-100"><Scale className="h-4 w-4" aria-hidden="true" /></span>
          <div>
            <h2 id="legal-notice-title" className="text-sm font-semibold text-amber-50">Information, not legal advice</h2>
            <p className="mt-1.5 max-w-5xl text-xs leading-5 text-amber-50/75">{legalDisclaimer}</p>
          </div>
        </div>
      </section>

      <section className="mt-8" aria-label="Filter legal references">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <div className="relative w-full xl:max-w-md">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" aria-hidden="true" />
            <input className="field pl-10" type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search laws, frameworks, topics…" aria-label="Search laws and frameworks" />
          </div>
          <div className="flex flex-wrap gap-2" role="group" aria-label="Filter by jurisdiction">
            {regions.map((item) => <button key={item} type="button" aria-pressed={region === item} onClick={() => setRegion(item)} className={`rounded-full border px-3 py-1.5 text-[11px] transition ${region === item ? "border-accent/35 bg-accent/[0.1] text-white" : "border-white/[0.08] text-slate-400 hover:border-white/[0.16] hover:text-slate-200"}`}>{item}</button>)}
          </div>
        </div>
        <div className="mt-3 flex gap-2 overflow-x-auto pb-1" role="group" aria-label="Filter by reference type">
          {categories.map((item) => <button key={item} type="button" aria-pressed={category === item} onClick={() => setCategory(item)} className={`shrink-0 rounded-md border px-2.5 py-1.5 text-[10px] transition ${category === item ? "border-slate-500 bg-white/[0.07] text-slate-100" : "border-transparent text-slate-500 hover:text-slate-300"}`}>{item}</button>)}
        </div>
      </section>

      <section className="mt-5 grid gap-3 lg:grid-cols-2" aria-label="Legal and cybersecurity references" aria-live="polite">
        {references.map((item) => (
          <article key={item.id} className="glass interactive-panel flex flex-col p-5 sm:p-6">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`rounded-full border px-2.5 py-1 text-[9px] font-medium uppercase tracking-[0.12em] ${categoryTone[item.category]}`}>{item.category}</span>
              <span className="rounded-full border border-white/[0.08] bg-white/[0.025] px-2.5 py-1 text-[9px] uppercase tracking-[0.12em] text-slate-400">{item.jurisdiction}</span>
            </div>
            <h2 className="mt-4 text-lg font-semibold tracking-[-0.02em] text-white">{item.title}</h2>
            <p className="mt-1 text-[11px] text-slate-500">{item.authority} <span aria-hidden="true">·</span> {item.published}</p>
            <p className="mt-4 text-sm leading-6 text-slate-300">{item.summary}</p>
            <div className="mt-4 rounded-lg border border-white/[0.06] bg-black/15 p-3.5">
              <p className="eyebrow !text-[9px] !tracking-[0.15em]">Scope and applicability</p>
              <p className="mt-1.5 text-xs leading-5 text-slate-400">{item.applicability}</p>
            </div>
            <div className="mt-auto flex flex-wrap items-end justify-between gap-3 pt-5">
              <div>
                <p className="font-mono text-[9px] text-slate-600">{item.version}</p>
                <p className="mt-1 text-[9px] text-slate-600">Source checked {item.verifiedAt}</p>
              </div>
              <a href={item.sourceUrl} target="_blank" rel="noopener noreferrer" className="btn-secondary !px-3 !py-2 text-[11px]">
                {item.sourceLabel}<ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
              </a>
            </div>
          </article>
        ))}
        {references.length === 0 && (
          <div className="glass col-span-full grid min-h-48 place-items-center p-8 text-center">
            <div><FileSearch className="mx-auto h-6 w-6 text-slate-600" aria-hidden="true" /><h2 className="mt-3 text-sm font-medium text-slate-200">No matching references</h2><p className="mt-1 text-xs text-slate-500">Adjust your search or filters to see other sources.</p></div>
          </div>
        )}
      </section>

      <p className="mt-6 text-center text-[10px] leading-5 text-slate-600">Official links point to primary government, regulator, or standards-body sources. Check current official materials before acting; this library does not certify compliance.</p>
    </div>
  );
}
