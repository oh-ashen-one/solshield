'use client';

import { useState, useMemo, useCallback } from 'react';
import Link from 'next/link';
import patternsData from '../../data/patterns.json';

// ============================================================
// TYPES
// ============================================================
interface Pattern {
  id: string;
  name: string;
  severity: string;
  category: string;
}

const patterns: Pattern[] = patternsData as Pattern[];

// ============================================================
// CONSTANTS
// ============================================================
const ITEMS_PER_PAGE = 50;

const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const severityConfig: Record<string, { badge: string; bg: string; text: string; dot: string }> = {
  critical: { badge: 'bg-red-500/15 text-red-400 border-red-500/25', bg: 'bg-red-500/8 border-red-500/15 hover:border-red-500/30', text: 'text-red-400', dot: 'bg-red-400' },
  high: { badge: 'bg-orange-500/15 text-orange-400 border-orange-500/25', bg: 'bg-orange-500/8 border-orange-500/15 hover:border-orange-500/30', text: 'text-orange-400', dot: 'bg-orange-400' },
  medium: { badge: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/25', bg: 'bg-yellow-500/8 border-yellow-500/15 hover:border-yellow-500/30', text: 'text-yellow-400', dot: 'bg-yellow-400' },
  low: { badge: 'bg-blue-500/15 text-blue-400 border-blue-500/25', bg: 'bg-blue-500/8 border-blue-500/15 hover:border-blue-500/30', text: 'text-blue-400', dot: 'bg-blue-400' },
  info: { badge: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/25', bg: 'bg-zinc-500/8 border-zinc-500/15 hover:border-zinc-500/30', text: 'text-zinc-400', dot: 'bg-zinc-400' },
};

const severities = ['critical', 'high', 'medium', 'low', 'info'];
const categories = [...new Set(patterns.map(p => p.category))].sort();

// Precompute counts
const severityCounts: Record<string, number> = {};
for (const s of severities) severityCounts[s] = patterns.filter(p => p.severity === s).length;
const categoryCounts: Record<string, number> = {};
for (const c of categories) categoryCounts[c] = patterns.filter(p => p.category === c).length;

// Category icons
const categoryIcons: Record<string, string> = {
  'Access Control': '🔐', 'Account Safety': '👤', 'Anchor': '⚓', 'Audit Methodology': '📋',
  'Bridge & Cross-Chain': '🌉', 'Business Logic': '🧩', 'CPI Security': '🔗', 'Core Security': '🛡️',
  'Data & Serialization': '📦', 'DeFi': '💰', 'Emerging Threats': '🚨', 'Governance': '🏛️',
  'Infrastructure': '🏗️', 'Math & Arithmetic': '🔢', 'NFT': '🎨', 'Operations': '⚙️',
  'Oracle Security': '🔮', 'Other': '📌', 'PDA Security': '🔑', 'Program Safety': '📜',
  'Real-World Exploits': '💥', 'Supply Chain': '📦', 'Token Security': '🪙', 'Wallet Security': '👛',
};

// ============================================================
// COMPONENT
// ============================================================
export default function PatternsPage() {
  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [expandedPattern, setExpandedPattern] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return patterns.filter(p => {
      if (selectedSeverity && p.severity !== selectedSeverity) return false;
      if (selectedCategory && p.category !== selectedCategory) return false;
      if (q && !p.name.toLowerCase().includes(q) && !p.id.toLowerCase().includes(q) && !p.category.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [search, selectedSeverity, selectedCategory]);

  const totalPages = Math.ceil(filtered.length / ITEMS_PER_PAGE);
  const currentPage = Math.min(page, totalPages || 1);
  const pageItems = filtered.slice((currentPage - 1) * ITEMS_PER_PAGE, currentPage * ITEMS_PER_PAGE);

  const clearFilters = useCallback(() => {
    setSearch(''); setSelectedSeverity(null); setSelectedCategory(null); setPage(1);
  }, []);

  const hasFilters = search || selectedSeverity || selectedCategory;

  // Filtered severity/category counts
  const filteredSevCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const s of severities) counts[s] = filtered.filter(p => p.severity === s).length;
    return counts;
  }, [filtered]);

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-100">
      {/* Header */}
      <header className="border-b border-zinc-800/50 backdrop-blur-md bg-[#0a0a0f]/70 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-400 to-cyan-600 flex items-center justify-center">
              <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <span className="text-lg font-bold tracking-tight">SolShield</span>
          </Link>
          <nav className="flex items-center gap-6">
            <Link href="/" className="text-sm text-zinc-400 hover:text-cyan-400 transition-colors">Home</Link>
            <Link href="/patterns" className="text-sm text-cyan-400 font-medium">Pattern Library</Link>
          </nav>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-8 sm:py-12">
        {/* Hero */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-3">
            <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">Pattern Library</h1>
            <span className="px-3 py-1 bg-cyan-500/10 border border-cyan-500/20 rounded-full text-cyan-400 text-sm font-medium">
              {patterns.length.toLocaleString()} patterns
            </span>
          </div>
          <p className="text-zinc-400 max-w-2xl text-sm sm:text-base">
            Browse every vulnerability pattern SolShield checks for. Built from real Solana exploits, audit reports, and security research — the most comprehensive Solana security database available.
          </p>
        </div>

        {/* Severity Stats */}
        <div className="grid grid-cols-5 gap-2 sm:gap-3 mb-6">
          {severities.map(sev => {
            const count = hasFilters ? filteredSevCounts[sev] : severityCounts[sev];
            const cfg = severityConfig[sev];
            const active = selectedSeverity === sev;
            return (
              <button
                key={sev}
                onClick={() => { setSelectedSeverity(active ? null : sev); setPage(1); }}
                className={`border rounded-xl p-3 sm:p-4 text-center transition-all ${cfg.bg} ${active ? 'ring-2 ring-cyan-500/50 ring-offset-1 ring-offset-[#0a0a0f]' : ''}`}
              >
                <div className={`text-xl sm:text-2xl font-bold ${cfg.text}`}>{count.toLocaleString()}</div>
                <div className="text-xs text-zinc-500 capitalize mt-0.5">{sev}</div>
              </button>
            );
          })}
        </div>

        {/* Search + Category Filter */}
        <div className="flex flex-col sm:flex-row gap-3 mb-6">
          <div className="relative flex-1">
            <svg className="absolute left-3 top-3 w-5 h-5 text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              placeholder="Search by name, ID (SOL001), or category..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              className="w-full pl-10 pr-4 py-2.5 bg-zinc-900/80 border border-zinc-700/50 rounded-xl text-white placeholder-zinc-500 text-sm focus:outline-none focus:border-cyan-500/50 transition"
            />
            {search && (
              <button onClick={() => { setSearch(''); setPage(1); }} className="absolute right-3 top-3 text-zinc-500 hover:text-white">
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            )}
          </div>
          <select
            value={selectedCategory || ''}
            onChange={(e) => { setSelectedCategory(e.target.value || null); setPage(1); }}
            className="px-4 py-2.5 bg-zinc-900/80 border border-zinc-700/50 rounded-xl text-sm text-zinc-300 focus:outline-none focus:border-cyan-500/50 transition min-w-[200px]"
          >
            <option value="">All Categories ({categories.length})</option>
            {categories.map(cat => (
              <option key={cat} value={cat}>{categoryIcons[cat] || '📌'} {cat} ({categoryCounts[cat]})</option>
            ))}
          </select>
          {hasFilters && (
            <button onClick={clearFilters} className="px-4 py-2.5 text-sm text-zinc-400 hover:text-white border border-zinc-700/50 rounded-xl hover:border-zinc-600 transition whitespace-nowrap">
              Clear all ×
            </button>
          )}
        </div>

        {/* Results info */}
        <div className="flex items-center justify-between mb-4">
          <p className="text-sm text-zinc-500">
            {hasFilters ? (
              <>Showing <span className="text-zinc-300 font-medium">{filtered.length.toLocaleString()}</span> of {patterns.length.toLocaleString()} patterns</>
            ) : (
              <>{patterns.length.toLocaleString()} vulnerability patterns</>
            )}
            {totalPages > 1 && <> &middot; Page {currentPage} of {totalPages}</>}
          </p>
          {totalPages > 1 && (
            <div className="flex items-center gap-1">
              <button
                disabled={currentPage <= 1}
                onClick={() => setPage(p => Math.max(1, p - 1))}
                className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 disabled:opacity-30 disabled:hover:bg-transparent transition"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" /></svg>
              </button>
              {/* Page numbers */}
              {(() => {
                const pages: (number | string)[] = [];
                if (totalPages <= 7) {
                  for (let i = 1; i <= totalPages; i++) pages.push(i);
                } else {
                  pages.push(1);
                  if (currentPage > 3) pages.push('...');
                  for (let i = Math.max(2, currentPage - 1); i <= Math.min(totalPages - 1, currentPage + 1); i++) pages.push(i);
                  if (currentPage < totalPages - 2) pages.push('...');
                  pages.push(totalPages);
                }
                return pages.map((p, i) =>
                  typeof p === 'string' ? (
                    <span key={`ellipsis-${i}`} className="px-1 text-zinc-600">…</span>
                  ) : (
                    <button
                      key={p}
                      onClick={() => setPage(p)}
                      className={`w-8 h-8 rounded-lg text-xs font-medium transition ${p === currentPage ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-zinc-400 hover:text-white hover:bg-zinc-800'}`}
                    >
                      {p}
                    </button>
                  )
                );
              })()}
              <button
                disabled={currentPage >= totalPages}
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 disabled:opacity-30 disabled:hover:bg-transparent transition"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" /></svg>
              </button>
            </div>
          )}
        </div>

        {/* Pattern List */}
        {pageItems.length > 0 ? (
          <div className="space-y-1.5">
            {/* Table header */}
            <div className="hidden sm:grid grid-cols-[80px_1fr_140px_180px] gap-3 px-4 py-2 text-xs text-zinc-600 font-medium uppercase tracking-wider">
              <span>ID</span>
              <span>Pattern</span>
              <span>Severity</span>
              <span>Category</span>
            </div>
            {pageItems.map(pattern => {
              const cfg = severityConfig[pattern.severity] || severityConfig.info;
              return (
                <div
                  key={pattern.id}
                  className="group grid grid-cols-1 sm:grid-cols-[80px_1fr_140px_180px] gap-1 sm:gap-3 items-center px-4 py-3 bg-zinc-900/30 border border-zinc-800/50 rounded-lg hover:border-zinc-700/80 hover:bg-zinc-900/50 transition-all cursor-default"
                >
                  <span className="font-mono text-cyan-400/80 text-sm">{pattern.id}</span>
                  <span className="text-sm text-zinc-200 group-hover:text-white transition-colors">{pattern.name}</span>
                  <span className="flex items-center gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
                    <span className={`text-xs font-medium capitalize ${cfg.text}`}>{pattern.severity}</span>
                  </span>
                  <span className="text-xs text-zinc-500">
                    {categoryIcons[pattern.category] || '📌'} {pattern.category}
                  </span>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center py-16">
            <div className="text-5xl mb-4">🔍</div>
            <p className="text-zinc-400 mb-2">No patterns match your filters</p>
            <p className="text-zinc-600 text-sm mb-6">Try adjusting your search or clearing filters</p>
            <button onClick={clearFilters} className="px-5 py-2.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 rounded-xl font-medium transition border border-cyan-500/20">
              Clear all filters
            </button>
          </div>
        )}

        {/* Bottom pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-6 pt-6 border-t border-zinc-800/50">
            <button
              disabled={currentPage <= 1}
              onClick={() => { setPage(p => Math.max(1, p - 1)); window.scrollTo({ top: 0, behavior: 'smooth' }); }}
              className="px-4 py-2 text-sm text-zinc-400 hover:text-white border border-zinc-700/50 rounded-lg hover:border-zinc-600 disabled:opacity-30 transition"
            >
              ← Previous
            </button>
            <span className="text-sm text-zinc-500">Page {currentPage} of {totalPages}</span>
            <button
              disabled={currentPage >= totalPages}
              onClick={() => { setPage(p => Math.min(totalPages, p + 1)); window.scrollTo({ top: 0, behavior: 'smooth' }); }}
              className="px-4 py-2 text-sm text-zinc-400 hover:text-white border border-zinc-700/50 rounded-lg hover:border-zinc-600 disabled:opacity-30 transition"
            >
              Next →
            </button>
          </div>
        )}

        {/* Category overview */}
        <div className="mt-12 pt-8 border-t border-zinc-800/50">
          <h2 className="text-xl font-bold mb-6">Categories Overview</h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
            {categories.map(cat => (
              <button
                key={cat}
                onClick={() => { setSelectedCategory(selectedCategory === cat ? null : cat); setPage(1); window.scrollTo({ top: 0, behavior: 'smooth' }); }}
                className={`p-4 rounded-xl border text-left transition-all ${
                  selectedCategory === cat
                    ? 'bg-cyan-500/10 border-cyan-500/30'
                    : 'bg-zinc-900/30 border-zinc-800/50 hover:border-zinc-700'
                }`}
              >
                <div className="text-lg mb-1">{categoryIcons[cat] || '📌'}</div>
                <div className="text-sm font-medium text-zinc-200">{cat}</div>
                <div className="text-xs text-zinc-500 mt-1">{categoryCounts[cat]} patterns</div>
              </button>
            ))}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-800/50 py-8 text-center text-zinc-600 text-sm">
        <p>SolShield — {patterns.length.toLocaleString()} vulnerability patterns for Solana security</p>
        <p className="mt-1">Built by Midir 🐉 for the Solana Agent Hackathon 2026</p>
      </footer>
    </div>
  );
}
