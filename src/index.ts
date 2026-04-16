import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { z } from "zod";

// ─── Types ────────────────────────────────────────────────────────────────────

interface NpmsPackage {
	package: {
		name: string;
		version: string;
		description: string;
		keywords?: string[];
		date: string;
		links: { npm: string; homepage?: string; repository?: string };
	};
	score: {
		final: number;
		detail: { quality: number; popularity: number; maintenance: number };
	};
}

interface NpmRegistry {
	"dist-tags": { latest: string };
	time: Record<string, string>;
	versions: Record<
		string,
		{
			dependencies?: Record<string, string>;
			devDependencies?: Record<string, string>;
			peerDependencies?: Record<string, string>;
			deprecated?: string;
			engines?: Record<string, string>;
		}
	>;
	license?: string;
	maintainers?: { name: string }[];
	repository?: { url?: string };
}

interface BundlephobiaResult {
	size: number;
	gzip: number;
	dependencyCount: number;
}

interface OsvVuln {
	id: string;
	summary?: string;
	severity?: { type: string; score: string }[];
	affected?: {
		ranges?: {
			type: string;
			events?: { introduced?: string; fixed?: string }[];
		}[];
	}[];
	references?: { url: string }[];
	published?: string;
}

interface OsvResponse {
	vulns?: OsvVuln[];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function fetchJson<T>(url: string): Promise<T | null> {
	try {
		const res = await fetch(url, {
			headers: { "User-Agent": "npm-advisor-mcp/0.2.0" },
			signal: AbortSignal.timeout(8000),
		});
		if (!res.ok) return null;
		return (await res.json()) as T;
	} catch {
		return null;
	}
}

async function postJson<T>(url: string, body: unknown): Promise<T | null> {
	try {
		const res = await fetch(url, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"User-Agent": "npm-advisor-mcp/0.2.0",
			},
			body: JSON.stringify(body),
			signal: AbortSignal.timeout(8000),
		});
		if (!res.ok) return null;
		return (await res.json()) as T;
	} catch {
		return null;
	}
}

function formatBytes(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kB`;
	return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function scoreLabel(score: number): string {
	if (score >= 0.8) return "Excellent";
	if (score >= 0.6) return "Good";
	if (score >= 0.4) return "Fair";
	return "Poor";
}

function monthsAgo(dateStr: string): string {
	const months = Math.floor(
		(Date.now() - new Date(dateStr).getTime()) / (1000 * 60 * 60 * 24 * 30),
	);
	if (months === 0) return "this month";
	if (months === 1) return "1 month ago";
	if (months < 12) return `${months} months ago`;
	const years = Math.floor(months / 12);
	return years === 1 ? "1 year ago" : `${years} years ago`;
}

// Open source license detection
const OPEN_SOURCE_LICENSES = new Set([
	"MIT",
	"ISC",
	"BSD-2-Clause",
	"BSD-3-Clause",
	"Apache-2.0",
	"GPL-2.0",
	"GPL-2.0-only",
	"GPL-3.0",
	"GPL-3.0-only",
	"LGPL-2.0",
	"LGPL-2.1",
	"LGPL-3.0",
	"MPL-2.0",
	"CDDL-1.0",
	"EPL-1.0",
	"EPL-2.0",
	"AGPL-3.0",
	"CC0-1.0",
	"Unlicense",
	"0BSD",
	"BlueOak-1.0.0",
	"Python-2.0",
	"Artistic-2.0",
]);

function isOpenSource(license: string | undefined): boolean {
	if (!license || license === "Unknown") return false;
	if (OPEN_SOURCE_LICENSES.has(license)) return true;
	return /^(MIT|ISC|Apache|BSD|GPL|LGPL|MPL|CC0|Unlicense|EUPL)/i.test(license);
}

function licenseTag(license: string | undefined): string {
	if (!license || license === "Unknown") return "❓ Unknown";
	return isOpenSource(license) ? `${license} ✅` : `${license} 🔒`;
}

// Stable version detection — excludes pre-release tags
function isStableVersion(v: string): boolean {
	return !/alpha|beta|rc|next|canary|experimental|\.dev|pre\.|nightly|insider/i.test(v);
}

function getLatestStable(registry: NpmRegistry): string | null {
	const allVersions = Object.keys(registry.versions ?? {});
	const stable = allVersions.filter(isStableVersion);
	if (stable.length === 0) return null;
	return stable.sort((a, b) => {
		const pa = a.split(".").map((x) => Number.parseInt(x) || 0);
		const pb = b.split(".").map((x) => Number.parseInt(x) || 0);
		for (let i = 0; i < 3; i++) {
			if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pb[i] ?? 0) - (pa[i] ?? 0);
		}
		return 0;
	})[0] ?? null;
}

// Determine if a semver range is outdated compared to latest stable
function isOutdated(currentRange: string, latestStable: string): boolean {
	// Extract numeric version from range (e.g. "^1.2.3" → "1.2.3")
	const match = currentRange.match(/(\d+)\.(\d+)\.(\d+)/);
	if (!match) return false;
	const cur = match.slice(1).map(Number);
	const lat = latestStable.split(".").map((x) => Number.parseInt(x) || 0);
	// Major version difference = definitely outdated
	if ((lat[0] ?? 0) > (cur[0] ?? 0)) return true;
	// Minor version difference
	if ((lat[0] ?? 0) === (cur[0] ?? 0) && (lat[1] ?? 0) > (cur[1] ?? 0) + 2) return true;
	return false;
}

// OSV vulnerability lookup
async function getVulnerabilities(name: string): Promise<OsvVuln[]> {
	const data = await postJson<OsvResponse>("https://api.osv.dev/v1/query", {
		package: { name, ecosystem: "npm" },
	});
	return data?.vulns ?? [];
}

function vulnSeverityEmoji(vulns: OsvVuln[]): string {
	if (vulns.length === 0) return "✅ None";
	const hasCritical = vulns.some((v) => {
		const score = Number.parseFloat(v.severity?.[0]?.score ?? "0");
		return score >= 9.0;
	});
	const hasHigh = vulns.some((v) => {
		const score = Number.parseFloat(v.severity?.[0]?.score ?? "0");
		return score >= 7.0;
	});
	if (hasCritical) return `🔴 ${vulns.length} (critical)`;
	if (hasHigh) return `🟠 ${vulns.length} (high)`;
	return `🟡 ${vulns.length}`;
}

function formatVulnList(vulns: OsvVuln[], limit = 5): string {
	if (vulns.length === 0) return "✅ No known vulnerabilities found.";
	const lines = vulns.slice(0, limit).map((v) => {
		const cvss = v.severity?.[0]?.score ? ` | CVSS: **${v.severity[0].score}**` : "";
		const fixed = v.affected
			?.flatMap((a) => a.ranges ?? [])
			.flatMap((r) => r.events ?? [])
			.find((e) => e.fixed)?.fixed;
		const fixedStr = fixed ? ` → Fixed in **v${fixed}**` : " → ⚠️ No fix yet";
		const ref = v.references?.[0]?.url ? ` ([details](${v.references[0].url}))` : "";
		return `- **${v.id}**${cvss}: ${v.summary ?? "No summary"}${fixedStr}${ref}`;
	});
	if (vulns.length > limit) lines.push(`- ...and **${vulns.length - limit}** more vulnerabilities`);
	return lines.join("\n");
}

async function getNpmsData(name: string): Promise<NpmsPackage | null> {
	return fetchJson<NpmsPackage>(`https://api.npms.io/v2/package/${encodeURIComponent(name)}`);
}

async function getNpmRegistry(name: string): Promise<NpmRegistry | null> {
	return fetchJson<NpmRegistry>(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
}

async function getBundleSize(name: string): Promise<BundlephobiaResult | null> {
	return fetchJson<BundlephobiaResult>(
		`https://bundlephobia.com/api/size?package=${encodeURIComponent(name)}@latest`,
	);
}

async function getWeeklyDownloads(name: string): Promise<number | null> {
	const data = await fetchJson<{ downloads: number }>(
		`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`,
	);
	return data?.downloads ?? null;
}

function buildPackageSummary(
	npms: NpmsPackage,
	registry: NpmRegistry | null,
	bundle: BundlephobiaResult | null,
	downloads: number | null,
	vulns?: OsvVuln[],
): string {
	const { package: pkg, score } = npms;
	const latest = registry?.["dist-tags"]?.latest ?? pkg.version;
	const latestStable = registry ? (getLatestStable(registry) ?? latest) : latest;
	const lastPublish = registry?.time?.[latest] ?? pkg.date;
	const deprecated = registry?.versions?.[latest]?.deprecated;
	const license = registry?.license ?? "Unknown";

	const lines = [
		`### ${pkg.name}@${latest}`,
		pkg.description ?? "",
		"",
		`| Metric | Value |`,
		`|--------|-------|`,
		`| Overall score | ${(score.final * 100).toFixed(0)}/100 (${scoreLabel(score.final)}) |`,
		`| Quality | ${(score.detail.quality * 100).toFixed(0)}/100 |`,
		`| Popularity | ${(score.detail.popularity * 100).toFixed(0)}/100 |`,
		`| Maintenance | ${(score.detail.maintenance * 100).toFixed(0)}/100 |`,
		`| Weekly downloads | ${downloads !== null ? downloads.toLocaleString() : "N/A"} |`,
		`| Last published | ${monthsAgo(lastPublish)} |`,
		`| License | ${licenseTag(license)} |`,
		`| Latest stable | v${latestStable}${latestStable !== latest ? ` *(dist-tag latest: ${latest})*` : ""} |`,
		`| Stable? | ${isStableVersion(latest) ? "✅ Yes" : "⚠️ Pre-release"} |`,
		`| Bundle size | ${bundle ? `${formatBytes(bundle.gzip)} gzip (${formatBytes(bundle.size)} raw)` : "N/A"} |`,
		`| Dependencies | ${bundle ? bundle.dependencyCount : "N/A"} |`,
		`| npm | ${pkg.links.npm} |`,
	];

	if (vulns !== undefined) {
		lines.push(`| Vulnerabilities | ${vulnSeverityEmoji(vulns)} |`);
	}

	if (pkg.links.repository) lines.push(`| Repository | ${pkg.links.repository} |`);
	if (deprecated) lines.unshift(`> ⚠️ DEPRECATED: ${deprecated}\n`);
	return lines.join("\n");
}

// ─── MCP Agent ────────────────────────────────────────────────────────────────

export class NpmAdvisorMCP extends McpAgent {
	server = new McpServer({ name: "npm-advisor", version: "0.2.0" });

	async init() {
		// ── Tool 1: search_packages ──────────────────────────────────────────────
		this.server.registerTool(
			"search_packages",
			{
				description:
					"Search npm packages and get a ranked top-5 comparison table with license (open source?), vulnerability count, stable version info, scores, and bundle size.",
				inputSchema: {
					query: z
						.string()
						.describe("What you need, e.g. 'accessible date picker for React'"),
					limit: z
						.number()
						.min(1)
						.max(10)
						.default(5)
						.describe("Number of results (default 5)"),
				},
			},
			async ({ query, limit }) => {
				const data = await fetchJson<{ results: NpmsPackage[]; total: number }>(
					`https://api.npms.io/v2/search?q=${encodeURIComponent(query)}&size=${limit}`,
				);
				if (!data || data.results.length === 0) {
					return {
						content: [{ type: "text" as const, text: `No packages found for: "${query}"` }],
					};
				}

				const enriched = await Promise.all(
					data.results.map(async (r) => {
						const [registry, bundle, downloads, vulns] = await Promise.all([
							getNpmRegistry(r.package.name),
							getBundleSize(r.package.name),
							getWeeklyDownloads(r.package.name),
							getVulnerabilities(r.package.name),
						]);
						return { r, registry, bundle, downloads, vulns };
					}),
				);

				// Top-5 summary table
				const tableHeader = [
					`## Top ${enriched.length} Results for: "${query}"`,
					`> Found ${data.total.toLocaleString()} total packages\n`,
					`| # | Package | Version | Score | Downloads/wk | License | Open Source | Stable | Vulns |`,
					`|---|---------|---------|-------|-------------|---------|------------|--------|-------|`,
				];

				const tableRows = enriched.map(({ r, registry, downloads, vulns }, i) => {
					const latest = registry?.["dist-tags"]?.latest ?? r.package.version;
					const latestStable = registry ? (getLatestStable(registry) ?? latest) : latest;
					const license = registry?.license ?? "?";
					const oss = isOpenSource(license) ? "✅" : "🔒";
					const stable = isStableVersion(latestStable) ? "✅" : "⚠️";
					const vulnStr = vulns.length === 0 ? "✅" : `⚠️ ${vulns.length}`;
					const dl = downloads !== null ? downloads.toLocaleString() : "N/A";
					return `| ${i + 1} | **${r.package.name}** | ${latestStable} | ${(r.score.final * 100).toFixed(0)}/100 | ${dl} | ${license} | ${oss} | ${stable} | ${vulnStr} |`;
				});

				const detailedCards = enriched.map(({ r, registry, bundle, downloads, vulns }, i) =>
					`**#${i + 1}**\n${buildPackageSummary(r, registry, bundle, downloads, vulns)}`,
				);

				const output = [
					[...tableHeader, ...tableRows].join("\n"),
					"---",
					"## Detailed Breakdown",
					...detailedCards,
				].join("\n\n---\n\n");

				return { content: [{ type: "text" as const, text: output }] };
			},
		);

		// ── Tool 2: compare_packages ─────────────────────────────────────────────
		this.server.registerTool(
			"compare_packages",
			{
				description:
					"Compare 2–5 npm packages side by side: scores, downloads, bundle size, license (open source?), stable version, and vulnerability count.",
				inputSchema: {
					packages: z
						.array(z.string())
						.min(2)
						.max(5)
						.describe("Package names, e.g. ['axios', 'got', 'node-fetch']"),
				},
			},
			async ({ packages }) => {
				const results = await Promise.all(
					packages.map(async (name) => {
						const [npms, registry, bundle, downloads, vulns] = await Promise.all([
							getNpmsData(name),
							getNpmRegistry(name),
							getBundleSize(name),
							getWeeklyDownloads(name),
							getVulnerabilities(name),
						]);
						return { name, npms, registry, bundle, downloads, vulns };
					}),
				);

				// Summary table
				const tableHeader = [
					`## Package Comparison`,
					`| Package | Version | Score | Downloads/wk | License | Open Source | Stable | Bundle (gzip) | Vulns |`,
					`|---------|---------|-------|-------------|---------|------------|--------|--------------|-------|`,
				];
				const tableRows = results.map(({ name, npms, registry, bundle, downloads, vulns }) => {
					if (!npms) return `| **${name}** | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |`;
					const latest = registry?.["dist-tags"]?.latest ?? npms.package.version;
					const latestStable = registry ? (getLatestStable(registry) ?? latest) : latest;
					const license = registry?.license ?? "?";
					const oss = isOpenSource(license) ? "✅" : "🔒";
					const stable = isStableVersion(latestStable) ? "✅" : "⚠️";
					const dl = downloads !== null ? downloads.toLocaleString() : "N/A";
					const bundleStr = bundle ? formatBytes(bundle.gzip) : "N/A";
					const vulnStr = vulns.length === 0 ? "✅" : `⚠️ ${vulns.length}`;
					return `| **${name}** | ${latestStable} | ${(npms.score.final * 100).toFixed(0)}/100 | ${dl} | ${license} | ${oss} | ${stable} | ${bundleStr} | ${vulnStr} |`;
				});

				// Detailed cards
				const cards = results.map(({ name, npms, registry, bundle, downloads, vulns }) => {
					if (!npms) return `### ${name}\n> Not found on npm`;
					const latest = registry?.["dist-tags"]?.latest ?? npms.package.version;
					const deprecated = registry?.versions?.[latest]?.deprecated;
					return [
						`### ${name}${deprecated ? " ⚠️ DEPRECATED" : ""}`,
						`- **Score:** ${(npms.score.final * 100).toFixed(0)}/100 | Quality: ${(npms.score.detail.quality * 100).toFixed(0)} | Popularity: ${(npms.score.detail.popularity * 100).toFixed(0)} | Maintenance: ${(npms.score.detail.maintenance * 100).toFixed(0)}`,
						`- **License:** ${licenseTag(registry?.license)}`,
						`- **Downloads/week:** ${downloads !== null ? downloads.toLocaleString() : "N/A"}`,
						`- **Last published:** ${monthsAgo(registry?.time?.[latest] ?? npms.package.date)}`,
						`- **Bundle:** ${bundle ? `${formatBytes(bundle.gzip)} gzip` : "N/A"} | **Deps:** ${bundle?.dependencyCount ?? "N/A"}`,
						`- **Vulnerabilities:** ${vulnSeverityEmoji(vulns)}`,
						vulns.length > 0 ? formatVulnList(vulns, 3) : "",
					]
						.filter(Boolean)
						.join("\n");
				});

				const winner = results
					.filter((r) => r.npms)
					.sort((a, b) => b.npms!.score.final - a.npms!.score.final)[0];

				const safestPick = results
					.filter((r) => r.npms)
					.sort((a, b) => {
						// Penalise vulnerabilities, reward score
						const scoreA = a.npms!.score.final - a.vulns.length * 0.05;
						const scoreB = b.npms!.score.final - b.vulns.length * 0.05;
						return scoreB - scoreA;
					})[0];

				const output = [
					[...tableHeader, ...tableRows].join("\n"),
					"---",
					"## Detailed Breakdown",
					...cards,
					"---",
					"## Recommendation",
					winner
						? `- **Highest score:** \`${winner.name}\` (${(winner.npms!.score.final * 100).toFixed(0)}/100)`
						: "",
					safestPick && safestPick.name !== winner?.name
						? `- **Safest choice (score + zero vulns):** \`${safestPick.name}\``
						: "",
				]
					.filter(Boolean)
					.join("\n\n---\n\n");

				return { content: [{ type: "text" as const, text: output }] };
			},
		);

		// ── Tool 3: audit_package ────────────────────────────────────────────────
		this.server.registerTool(
			"audit_package",
			{
				description:
					"Deep audit of a single npm package: scores, license, open source status, stable vs latest version, known vulnerabilities (CVEs), bundle size, dependencies, and maintainers.",
				inputSchema: {
					name: z.string().describe("Package name, e.g. 'lodash'"),
				},
			},
			async ({ name }) => {
				const [npms, registry, bundle, downloads, vulns] = await Promise.all([
					getNpmsData(name),
					getNpmRegistry(name),
					getBundleSize(name),
					getWeeklyDownloads(name),
					getVulnerabilities(name),
				]);

				if (!npms) {
					return {
						content: [{ type: "text" as const, text: `Package "${name}" not found.` }],
					};
				}

				const latest = registry?.["dist-tags"]?.latest ?? npms.package.version;
				const latestStable = registry ? (getLatestStable(registry) ?? latest) : latest;
				const deprecated = registry?.versions?.[latest]?.deprecated;
				const license = registry?.license ?? "Unknown";
				const deps = Object.keys(registry?.versions?.[latest]?.dependencies ?? {});
				const peerDeps = Object.keys(registry?.versions?.[latest]?.peerDependencies ?? {});
				const engines = registry?.versions?.[latest]?.engines ?? {};

				const lines = [
					`## Audit: ${name}`,
					deprecated ? `> ⚠️ **DEPRECATED:** ${deprecated}` : "",
					npms.package.description ?? "",
					"",
					`**Latest tag:** v${latest} | **Latest stable:** v${latestStable}${latestStable !== latest ? " *(different!)*" : ""}`,
					`**Stable:** ${isStableVersion(latest) ? "✅ Yes" : "⚠️ Pre-release"}`,
					`**License:** ${licenseTag(license)} | **Open Source:** ${isOpenSource(license) ? "✅ Yes" : "🔒 No"}`,
					`**Published:** ${monthsAgo(registry?.time?.[latest] ?? npms.package.date)}`,
					`**Maintainers:** ${registry?.maintainers?.map((m) => m.name).join(", ") ?? "Unknown"}`,
					Object.keys(engines).length > 0
						? `**Engines:** ${Object.entries(engines)
								.map(([k, v]) => `${k}: ${v}`)
								.join(", ")}`
						: "",
					"",
					`### Scores`,
					`| Metric | Score | Rating |`,
					`|--------|-------|--------|`,
					`| Overall | ${(npms.score.final * 100).toFixed(0)}/100 | ${scoreLabel(npms.score.final)} |`,
					`| Quality | ${(npms.score.detail.quality * 100).toFixed(0)}/100 | ${scoreLabel(npms.score.detail.quality)} |`,
					`| Popularity | ${(npms.score.detail.popularity * 100).toFixed(0)}/100 | ${scoreLabel(npms.score.detail.popularity)} |`,
					`| Maintenance | ${(npms.score.detail.maintenance * 100).toFixed(0)}/100 | ${scoreLabel(npms.score.detail.maintenance)} |`,
					`| Weekly downloads | ${downloads !== null ? downloads.toLocaleString() : "N/A"} | — |`,
					bundle
						? `| Bundle (gzip) | ${formatBytes(bundle.gzip)} | ${formatBytes(bundle.size)} raw |`
						: "",
					bundle ? `| Dep count | ${bundle.dependencyCount} | — |` : "",
					"",
					`### Security`,
					formatVulnList(vulns),
					"",
					deps.length > 0
						? `### Runtime Dependencies (${deps.length})\n${deps.slice(0, 25).join(", ")}${deps.length > 25 ? ` ...+${deps.length - 25} more` : ""}`
						: "### No runtime dependencies",
					peerDeps.length > 0 ? `### Peer Dependencies\n${peerDeps.join(", ")}` : "",
					"",
					`### Links`,
					`- npm: ${npms.package.links.npm}`,
					npms.package.links.repository ? `- Repo: ${npms.package.links.repository}` : "",
					npms.package.links.homepage ? `- Homepage: ${npms.package.links.homepage}` : "",
				]
					.filter((l) => l !== undefined)
					.join("\n");

				return { content: [{ type: "text" as const, text: lines }] };
			},
		);

		// ── Tool 4: check_vulnerabilities ────────────────────────────────────────
		this.server.registerTool(
			"check_vulnerabilities",
			{
				description:
					"Check one or more npm packages for known CVEs and security vulnerabilities using the OSV database. Shows severity, affected versions, and fix versions.",
				inputSchema: {
					packages: z
						.array(z.string())
						.min(1)
						.max(20)
						.describe("Package names to check, e.g. ['lodash', 'axios']"),
				},
			},
			async ({ packages }) => {
				const results = await Promise.all(
					packages.map(async (name) => {
						const [vulns, registry] = await Promise.all([
							getVulnerabilities(name),
							getNpmRegistry(name),
						]);
						const latest = registry?.["dist-tags"]?.latest ?? "unknown";
						return { name, vulns, latest };
					}),
				);

				const sections = results.map(({ name, vulns, latest }) => {
					const header = `### ${name} (latest: v${latest}) — ${vulnSeverityEmoji(vulns)}`;
					return [header, formatVulnList(vulns)].join("\n");
				});

				// Summary table
				const tableHeader = [
					`## Vulnerability Report`,
					`| Package | Latest | Vulnerabilities | Severity |`,
					`|---------|--------|----------------|---------|`,
				];
				const tableRows = results.map(({ name, vulns, latest }) => {
					const critical = vulns.filter(
						(v) => Number.parseFloat(v.severity?.[0]?.score ?? "0") >= 9,
					).length;
					const high = vulns.filter(
						(v) =>
							Number.parseFloat(v.severity?.[0]?.score ?? "0") >= 7 &&
							Number.parseFloat(v.severity?.[0]?.score ?? "0") < 9,
					).length;
					const severityStr =
						vulns.length === 0
							? "✅ Clean"
							: `${critical > 0 ? `🔴 ${critical} critical ` : ""}${high > 0 ? `🟠 ${high} high` : ""}${critical === 0 && high === 0 ? "🟡 medium/low" : ""}`.trim();
					return `| **${name}** | ${latest} | ${vulns.length} | ${severityStr} |`;
				});

				const output = [
					[...tableHeader, ...tableRows].join("\n"),
					"---",
					"## Details",
					...sections,
				].join("\n\n");

				return { content: [{ type: "text" as const, text: output }] };
			},
		);

		// ── Tool 5: check_alternatives ───────────────────────────────────────────
		this.server.registerTool(
			"check_alternatives",
			{
				description:
					"Find better or safer alternatives to an npm package. Useful when a package is deprecated, unmaintained, or has vulnerabilities.",
				inputSchema: {
					name: z.string().describe("Package to find alternatives for, e.g. 'request'"),
				},
			},
			async ({ name }) => {
				const [original, registry, vulns] = await Promise.all([
					getNpmsData(name),
					getNpmRegistry(name),
					getVulnerabilities(name),
				]);
				if (!original) {
					return {
						content: [{ type: "text" as const, text: `Package "${name}" not found.` }],
					};
				}

				const keywords = original.package.keywords?.slice(0, 3) ?? [];
				const searchQuery = keywords.length > 0 ? keywords.join(" ") : name;
				const searchData = await fetchJson<{ results: NpmsPackage[] }>(
					`https://api.npms.io/v2/search?q=${encodeURIComponent(searchQuery)}&size=8`,
				);
				const alternatives = (searchData?.results ?? [])
					.filter((r) => r.package.name !== name)
					.slice(0, 4);

				const latest = registry?.["dist-tags"]?.latest ?? original.package.version;
				const deprecated = registry?.versions?.[latest]?.deprecated;
				const downloads = await getWeeklyDownloads(name);

				const summaries = await Promise.all(
					alternatives.map(async (r) => {
						const [reg, bundle, dl, altVulns] = await Promise.all([
							getNpmRegistry(r.package.name),
							getBundleSize(r.package.name),
							getWeeklyDownloads(r.package.name),
							getVulnerabilities(r.package.name),
						]);
						return buildPackageSummary(r, reg, bundle, dl, altVulns);
					}),
				);

				const output = [
					`## Alternatives to \`${name}\``,
					deprecated
						? `> ⚠️ \`${name}\` is **deprecated**: ${deprecated}`
						: `> Score: ${(original.score.final * 100).toFixed(0)}/100 | ${downloads?.toLocaleString() ?? "N/A"} downloads/week | ${vulns.length > 0 ? `⚠️ ${vulns.length} vulnerabilities` : "✅ No known vulnerabilities"}`,
					summaries.length > 0
						? `### Top alternatives:\n\n${summaries.join("\n\n---\n\n")}`
						: "No alternatives found.",
				].join("\n\n");

				return { content: [{ type: "text" as const, text: output }] };
			},
		);

		// ── Tool 6: scan_project_deps ────────────────────────────────────────────
		this.server.registerTool(
			"scan_project_deps",
			{
				description:
					"Audit all dependencies in a package.json. Shows each package's current version vs latest stable, vulnerability count, maintenance health, deprecation status, and upgrade recommendations.",
				inputSchema: {
					package_json: z.string().describe("Full contents of a package.json file"),
				},
			},
			async ({ package_json }) => {
				let parsed: {
					dependencies?: Record<string, string>;
					devDependencies?: Record<string, string>;
					name?: string;
					engines?: Record<string, string>;
				};
				try {
					parsed = JSON.parse(package_json);
				} catch {
					return {
						content: [
							{
								type: "text" as const,
								text: "Invalid JSON. Please paste the full package.json content.",
							},
						],
					};
				}

				const depEntries = Object.entries(parsed.dependencies ?? {}).map(([n, v]) => ({
					name: n,
					range: v,
					dev: false,
				}));
				const devEntries = Object.entries(parsed.devDependencies ?? {}).map(([n, v]) => ({
					name: n,
					range: v,
					dev: true,
				}));
				const all = [...depEntries, ...devEntries].slice(0, 30);

				const results = await Promise.all(
					all.map(async ({ name, range, dev }) => {
						const [npms, registry, vulns] = await Promise.all([
							getNpmsData(name),
							getNpmRegistry(name),
							getVulnerabilities(name),
						]);
						const latest = registry?.["dist-tags"]?.latest;
						const latestStable = registry ? (getLatestStable(registry) ?? latest ?? "?") : "?";
						const deprecated = latest ? registry?.versions?.[latest]?.deprecated : undefined;
						const outdated = latestStable !== "?" ? isOutdated(range, latestStable) : false;
						return {
							name,
							range,
							dev,
							score: npms?.score.final ?? 0,
							maintenance: npms?.score.detail.maintenance ?? 0,
							deprecated,
							latestStable,
							lastPublish:
								latest && registry?.time?.[latest]
									? monthsAgo(registry.time[latest])
									: "unknown",
							vulns,
							outdated,
							license: registry?.license ?? "Unknown",
						};
					}),
				);

				const deprecated = results.filter((r) => r.deprecated);
				const vulnerable = results.filter((r) => !r.deprecated && r.vulns.length > 0);
				const outdated = results.filter(
					(r) => !r.deprecated && r.vulns.length === 0 && r.outdated,
				);
				const lowMaintenance = results.filter(
					(r) => !r.deprecated && r.vulns.length === 0 && !r.outdated && r.maintenance < 0.4,
				);
				const healthy = results.filter(
					(r) =>
						!r.deprecated && r.vulns.length === 0 && !r.outdated && r.maintenance >= 0.4,
				);

				// Full summary table
				const tableHeader = [
					`## Dependency Audit: ${parsed.name ?? "project"}`,
					`Scanned **${all.length}** packages (${depEntries.length} deps + ${devEntries.length} devDeps)\n`,
					`| Package | Type | In package.json | Latest Stable | Outdated? | Vulns | Maintenance | Status |`,
					`|---------|------|----------------|--------------|----------|-------|------------|--------|`,
				];
				const tableRows = results.map((r) => {
					const type = r.dev ? "dev" : "dep";
					const outdatedStr = r.outdated ? "⚠️ Yes" : "✅ No";
					const vulnStr = r.vulns.length === 0 ? "✅" : `⚠️ ${r.vulns.length}`;
					const maint = `${(r.maintenance * 100).toFixed(0)}/100`;
					const status = r.deprecated
						? "🔴 DEPRECATED"
						: r.vulns.length > 0
							? "🟠 VULNERABLE"
							: r.outdated
								? "🟡 OUTDATED"
								: r.maintenance < 0.4
									? "🔴 UNMAINTAINED"
									: "✅ OK";
					return `| \`${r.name}\` | ${type} | \`${r.range}\` | \`${r.latestStable}\` | ${outdatedStr} | ${vulnStr} | ${maint} | ${status} |`;
				});

				const sections: string[] = [];

				if (deprecated.length > 0) {
					sections.push(
						`### 🔴 Deprecated (${deprecated.length})\n${deprecated.map((r) => `- **\`${r.name}\`** — ${r.deprecated}\n  → Search for alternatives`).join("\n")}`,
					);
				}

				if (vulnerable.length > 0) {
					sections.push(
						`### 🟠 Vulnerable (${vulnerable.length})\n${vulnerable
							.map((r) => {
								const fixedVersions = r.vulns
									.map(
										(v) =>
											v.affected
												?.flatMap((a) => a.ranges ?? [])
												.flatMap((rng) => rng.events ?? [])
												.find((e) => e.fixed)?.fixed,
									)
									.filter(Boolean);
								const fixStr =
									fixedVersions.length > 0
										? ` → Upgrade to **v${fixedVersions[0]}** or later`
										: " → No upstream fix yet";
								return `- **\`${r.name}\`** — ${r.vulns.length} vulnerability(s)${fixStr}`;
							})
							.join("\n")}`,
					);
				}

				if (outdated.length > 0) {
					sections.push(
						`### 🟡 Outdated (${outdated.length})\n${outdated.map((r) => `- **\`${r.name}\`** — using \`${r.range}\`, latest stable: **v${r.latestStable}**`).join("\n")}`,
					);
				}

				if (lowMaintenance.length > 0) {
					sections.push(
						`### 🔴 Low Maintenance (${lowMaintenance.length})\n${lowMaintenance.map((r) => `- **\`${r.name}\`** — maintenance: ${(r.maintenance * 100).toFixed(0)}/100, last published: ${r.lastPublish}`).join("\n")}`,
					);
				}

				if (healthy.length > 0) {
					sections.push(
						`### ✅ Healthy (${healthy.length})\n${healthy.map((r) => `- \`${r.name}\` — v${r.latestStable}, ${(r.score * 100).toFixed(0)}/100 score`).join("\n")}`,
					);
				}

				const output = [
					[...tableHeader, ...tableRows].join("\n"),
					"---",
					...sections,
				].join("\n\n");

				return { content: [{ type: "text" as const, text: output }] };
			},
		);

		// ── Tool 7: smart_upgrade_advisor ────────────────────────────────────────
		this.server.registerTool(
			"smart_upgrade_advisor",
			{
				description:
					"Analyze a project's package.json and give smart upgrade recommendations: which packages to upgrade urgently (security), which are safe to upgrade, which need caution (breaking changes), and the recommended version for each.",
				inputSchema: {
					package_json: z.string().describe("Full contents of a package.json file"),
				},
			},
			async ({ package_json }) => {
				let parsed: {
					dependencies?: Record<string, string>;
					devDependencies?: Record<string, string>;
					name?: string;
					engines?: Record<string, string>;
				};
				try {
					parsed = JSON.parse(package_json);
				} catch {
					return {
						content: [
							{
								type: "text" as const,
								text: "Invalid JSON. Please paste the full package.json content.",
							},
						],
					};
				}

				const allDeps = {
					...parsed.dependencies,
					...parsed.devDependencies,
				};
				const names = Object.keys(allDeps).slice(0, 25);

				const results = await Promise.all(
					names.map(async (name) => {
						const currentRange = allDeps[name] ?? "*";
						const [registry, vulns] = await Promise.all([
							getNpmRegistry(name),
							getVulnerabilities(name),
						]);
						const latest = registry?.["dist-tags"]?.latest ?? "?";
						const latestStable = registry ? (getLatestStable(registry) ?? latest) : latest;
						const deprecated = latest !== "?" ? registry?.versions?.[latest]?.deprecated : undefined;
						const outdated = latestStable !== "?" ? isOutdated(currentRange, latestStable) : false;

						// Determine if it's a major version bump (potentially breaking)
						const curMajor = Number.parseInt(currentRange.replace(/[^\d]/, "")) || 0;
						const latMajor = Number.parseInt(latestStable) || 0;
						const isMajorBump = latMajor > curMajor;

						// Priority scoring
						let priority: "URGENT" | "RECOMMENDED" | "OPTIONAL" | "OK" = "OK";
						if (vulns.length > 0 || deprecated) priority = "URGENT";
						else if (outdated && isMajorBump) priority = "RECOMMENDED";
						else if (outdated) priority = "RECOMMENDED";

						return {
							name,
							currentRange,
							latestStable,
							deprecated,
							outdated,
							isMajorBump,
							vulns,
							priority,
						};
					}),
				);

				const urgent = results.filter((r) => r.priority === "URGENT");
				const recommended = results.filter((r) => r.priority === "RECOMMENDED");
				const ok = results.filter((r) => r.priority === "OK");

				const lines = [
					`## Smart Upgrade Advisor: ${parsed.name ?? "project"}`,
					`Analyzed **${names.length}** packages\n`,
					urgent.length > 0
						? [
								`### 🔴 Urgent — Fix Immediately (${urgent.length})`,
								...urgent.map((r) => {
									const reasons: string[] = [];
									if (r.deprecated) reasons.push(`deprecated: ${r.deprecated}`);
									if (r.vulns.length > 0) reasons.push(`${r.vulns.length} CVE(s)`);
									const fixedVersion = r.vulns
										.map(
											(v) =>
												v.affected
													?.flatMap((a) => a.ranges ?? [])
													.flatMap((rng) => rng.events ?? [])
													.find((e) => e.fixed)?.fixed,
										)
										.filter(Boolean)[0];
									const upgradeStr = fixedVersion
										? `Upgrade to **v${fixedVersion}** (first patched)`
										: `Upgrade to latest stable **v${r.latestStable}**`;
									return `- \`${r.name}\` (${r.currentRange}) → ${upgradeStr}\n  Reason: ${reasons.join(", ")}`;
								}),
							].join("\n")
						: "### 🔴 Urgent\nNone — no critical issues found! 🎉",

					recommended.length > 0
						? [
								`### 🟡 Recommended Upgrades (${recommended.length})`,
								...recommended.map((r) => {
									const breakingNote = r.isMajorBump
										? " *(major version bump — check changelog for breaking changes)*"
										: "";
									return `- \`${r.name}\` (${r.currentRange}) → **v${r.latestStable}**${breakingNote}`;
								}),
							].join("\n")
						: "",

					ok.length > 0
						? [
								`### ✅ Up-to-date (${ok.length})`,
								ok.map((r) => `- \`${r.name}\` — v${r.latestStable}`).join("\n"),
							].join("\n")
						: "",

					`---`,
					`### Quick install commands`,
					urgent.length > 0
						? `**Urgent fixes:**\n\`\`\`\nnpm install ${urgent.map((r) => `${r.name}@${r.latestStable}`).join(" ")}\n\`\`\``
						: "",
					recommended.length > 0
						? `**Recommended upgrades:**\n\`\`\`\nnpm install ${recommended.map((r) => `${r.name}@${r.latestStable}`).join(" ")}\n\`\`\``
						: "",
				]
					.filter(Boolean)
					.join("\n\n");

				return { content: [{ type: "text" as const, text: lines }] };
			},
		);
	}
}

// ─── Worker entry ─────────────────────────────────────────────────────────────

export default {
	fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);
		if (url.pathname === "/sse" || url.pathname === "/sse/message") {
			return NpmAdvisorMCP.serveSSE("/sse").fetch(request, env, ctx);
		}
		if (url.pathname === "/mcp") {
			return NpmAdvisorMCP.serve("/mcp").fetch(request, env, ctx);
		}
		return new Response(
			JSON.stringify({
				name: "npm-advisor-mcp",
				version: "0.2.0",
				endpoints: { sse: "/sse", mcp: "/mcp" },
				tools: [
					"search_packages",
					"compare_packages",
					"audit_package",
					"check_vulnerabilities",
					"check_alternatives",
					"scan_project_deps",
					"smart_upgrade_advisor",
				],
			}),
			{ status: 200, headers: { "Content-Type": "application/json" } },
		);
	},
};
