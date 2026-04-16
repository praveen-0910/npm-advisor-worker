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
	versions: Record<string, { dependencies?: Record<string, string>; deprecated?: string }>;
	license?: string;
	maintainers?: { name: string }[];
}

interface BundlephobiaResult {
	size: number;
	gzip: number;
	dependencyCount: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function fetchJson<T>(url: string): Promise<T | null> {
	try {
		const res = await fetch(url, {
			headers: { "User-Agent": "npm-advisor-mcp/0.1.0" },
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
	const months = Math.floor((Date.now() - new Date(dateStr).getTime()) / (1000 * 60 * 60 * 24 * 30));
	if (months === 0) return "this month";
	if (months === 1) return "1 month ago";
	if (months < 12) return `${months} months ago`;
	const years = Math.floor(months / 12);
	return years === 1 ? "1 year ago" : `${years} years ago`;
}

async function getNpmsData(name: string): Promise<NpmsPackage | null> {
	return fetchJson<NpmsPackage>(`https://api.npms.io/v2/package/${encodeURIComponent(name)}`);
}

async function getNpmRegistry(name: string): Promise<NpmRegistry | null> {
	return fetchJson<NpmRegistry>(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
}

async function getBundleSize(name: string): Promise<BundlephobiaResult | null> {
	return fetchJson<BundlephobiaResult>(`https://bundlephobia.com/api/size?package=${encodeURIComponent(name)}@latest`);
}

async function getWeeklyDownloads(name: string): Promise<number | null> {
	const data = await fetchJson<{ downloads: number }>(
		`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`
	);
	return data?.downloads ?? null;
}

function buildPackageSummary(
	npms: NpmsPackage,
	registry: NpmRegistry | null,
	bundle: BundlephobiaResult | null,
	downloads: number | null
): string {
	const { package: pkg, score } = npms;
	const latest = registry?.["dist-tags"]?.latest ?? pkg.version;
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
		`| License | ${license} |`,
		`| Bundle size | ${bundle ? `${formatBytes(bundle.gzip)} gzip (${formatBytes(bundle.size)} raw)` : "N/A"} |`,
		`| Dependencies | ${bundle ? bundle.dependencyCount : "N/A"} |`,
		`| npm | ${pkg.links.npm} |`,
	];

	if (deprecated) lines.unshift(`> ⚠️ DEPRECATED: ${deprecated}\n`);
	return lines.join("\n");
}

// ─── MCP Agent ────────────────────────────────────────────────────────────────

export class NpmAdvisorMCP extends McpAgent {
	server = new McpServer({ name: "npm-advisor", version: "0.1.0" });

	async init() {

		// Tool 1 — search_packages
		this.server.registerTool(
			"search_packages",
			{
				description: "Search for npm packages based on natural language requirements. Returns ranked results scored on downloads, maintenance, quality, and bundle size.",
				inputSchema: {
					query: z.string().describe("What the user needs, e.g. 'accessible date picker for React'"),
					limit: z.number().min(1).max(10).default(5).describe("Number of results (default 5)"),
				},
			},
			async ({ query, limit }) => {
				const data = await fetchJson<{ results: NpmsPackage[]; total: number }>(
					`https://api.npms.io/v2/search?q=${encodeURIComponent(query)}&size=${limit}`
				);
				if (!data || data.results.length === 0) {
					return { content: [{ type: "text" as const, text: `No packages found for: "${query}"` }] };
				}
				const results = await Promise.all(
					data.results.map(async (r) => {
						const [registry, bundle, downloads] = await Promise.all([
							getNpmRegistry(r.package.name),
							getBundleSize(r.package.name),
							getWeeklyDownloads(r.package.name),
						]);
						return buildPackageSummary(r, registry, bundle, downloads);
					})
				);
				const output = [
					`## NPM Package Recommendations for: "${query}"`,
					`Found ${data.total.toLocaleString()} packages — showing top ${data.results.length} ranked by score:\n`,
					...results.map((r, i) => `**#${i + 1}**\n${r}`),
				].join("\n\n---\n\n");
				return { content: [{ type: "text" as const, text: output }] };
			}
		);

		// Tool 2 — compare_packages
		this.server.registerTool(
			"compare_packages",
			{
				description: "Compare 2–5 npm packages side by side on downloads, maintenance, bundle size, and overall scores.",
				inputSchema: {
					packages: z.array(z.string()).min(2).max(5).describe("Package names, e.g. ['axios', 'got', 'node-fetch']"),
				},
			},
			async ({ packages }) => {
				const results = await Promise.all(
					packages.map(async (name) => {
						const [npms, registry, bundle, downloads] = await Promise.all([
							getNpmsData(name), getNpmRegistry(name), getBundleSize(name), getWeeklyDownloads(name),
						]);
						return { name, npms, registry, bundle, downloads };
					})
				);
				const rows = results.map(({ name, npms, registry, bundle, downloads }) => {
					if (!npms) return `- **${name}**: Not found`;
					const latest = registry?.["dist-tags"]?.latest ?? npms.package.version;
					const deprecated = registry?.versions?.[latest]?.deprecated;
					return [
						`### ${name}${deprecated ? " ⚠️ DEPRECATED" : ""}`,
						`- **Score:** ${(npms.score.final * 100).toFixed(0)}/100`,
						`- **Quality / Popularity / Maintenance:** ${(npms.score.detail.quality * 100).toFixed(0)} / ${(npms.score.detail.popularity * 100).toFixed(0)} / ${(npms.score.detail.maintenance * 100).toFixed(0)}`,
						`- **Downloads/week:** ${downloads !== null ? downloads.toLocaleString() : "N/A"}`,
						`- **Last published:** ${monthsAgo(registry?.time?.[latest] ?? npms.package.date)}`,
						`- **Bundle:** ${bundle ? `${formatBytes(bundle.gzip)} gzip` : "N/A"} | **Deps:** ${bundle?.dependencyCount ?? "N/A"}`,
						`- **License:** ${registry?.license ?? "Unknown"}`,
					].join("\n");
				});
				const winner = results.filter((r) => r.npms).sort((a, b) => b.npms!.score.final - a.npms!.score.final)[0];
				const output = [
					`## Package Comparison`,
					...rows,
					winner ? `## Recommendation\n**${winner.name}** has the highest overall score (${(winner.npms!.score.final * 100).toFixed(0)}/100).` : "",
				].join("\n\n---\n\n");
				return { content: [{ type: "text" as const, text: output }] };
			}
		);

		// Tool 3 — audit_package
		this.server.registerTool(
			"audit_package",
			{
				description: "Deep dive audit of a single npm package. Returns scores, deprecation status, bundle size, dependencies, and maintainers.",
				inputSchema: {
					name: z.string().describe("Package name, e.g. 'lodash'"),
				},
			},
			async ({ name }) => {
				const [npms, registry, bundle, downloads] = await Promise.all([
					getNpmsData(name), getNpmRegistry(name), getBundleSize(name), getWeeklyDownloads(name),
				]);
				if (!npms) return { content: [{ type: "text" as const, text: `Package "${name}" not found.` }] };
				const latest = registry?.["dist-tags"]?.latest ?? npms.package.version;
				const deprecated = registry?.versions?.[latest]?.deprecated;
				const deps = Object.keys(registry?.versions?.[latest]?.dependencies ?? {});
				const lines = [
					`## Audit: ${name}`,
					deprecated ? `> ⚠️ **DEPRECATED:** ${deprecated}` : "",
					npms.package.description ?? "",
					`**Version:** ${latest} | **License:** ${registry?.license ?? "Unknown"} | **Published:** ${monthsAgo(registry?.time?.[latest] ?? npms.package.date)}`,
					`**Maintainers:** ${registry?.maintainers?.map((m) => m.name).join(", ") ?? "Unknown"}`,
					`### Scores`,
					`| Metric | Score | Rating |`,
					`|--------|-------|--------|`,
					`| Overall | ${(npms.score.final * 100).toFixed(0)}/100 | ${scoreLabel(npms.score.final)} |`,
					`| Quality | ${(npms.score.detail.quality * 100).toFixed(0)}/100 | ${scoreLabel(npms.score.detail.quality)} |`,
					`| Popularity | ${(npms.score.detail.popularity * 100).toFixed(0)}/100 | ${scoreLabel(npms.score.detail.popularity)} |`,
					`| Maintenance | ${(npms.score.detail.maintenance * 100).toFixed(0)}/100 | ${scoreLabel(npms.score.detail.maintenance)} |`,
					`- **Weekly downloads:** ${downloads !== null ? downloads.toLocaleString() : "N/A"}`,
					bundle ? `- **Bundle:** ${formatBytes(bundle.size)} raw / ${formatBytes(bundle.gzip)} gzip | **Deps:** ${bundle.dependencyCount}` : "",
					deps.length > 0 ? `### Dependencies (${deps.length})\n${deps.slice(0, 20).join(", ")}` : "### No dependencies",
					`- npm: ${npms.package.links.npm}`,
					npms.package.links.repository ? `- Repo: ${npms.package.links.repository}` : "",
				].filter(Boolean).join("\n");
				return { content: [{ type: "text" as const, text: lines }] };
			}
		);

		// Tool 4 — check_alternatives
		this.server.registerTool(
			"check_alternatives",
			{
				description: "Find better alternatives to a given npm package. Useful when a package is deprecated or unmaintained.",
				inputSchema: {
					name: z.string().describe("Package to find alternatives for, e.g. 'request'"),
				},
			},
			async ({ name }) => {
				const [original, registry] = await Promise.all([getNpmsData(name), getNpmRegistry(name)]);
				if (!original) return { content: [{ type: "text" as const, text: `Package "${name}" not found.` }] };
				const keywords = original.package.keywords?.slice(0, 3) ?? [];
				const searchQuery = keywords.length > 0 ? keywords.join(" ") : name;
				const searchData = await fetchJson<{ results: NpmsPackage[] }>(
					`https://api.npms.io/v2/search?q=${encodeURIComponent(searchQuery)}&size=8`
				);
				const alternatives = (searchData?.results ?? []).filter((r) => r.package.name !== name).slice(0, 4);
				const latest = registry?.["dist-tags"]?.latest ?? original.package.version;
				const deprecated = registry?.versions?.[latest]?.deprecated;
				const downloads = await getWeeklyDownloads(name);
				const summaries = await Promise.all(
					alternatives.map(async (r) => {
						const [reg, bundle, dl] = await Promise.all([getNpmRegistry(r.package.name), getBundleSize(r.package.name), getWeeklyDownloads(r.package.name)]);
						return buildPackageSummary(r, reg, bundle, dl);
					})
				);
				const output = [
					`## Alternatives to \`${name}\``,
					deprecated ? `> ⚠️ \`${name}\` is **deprecated**: ${deprecated}` : `> Score: ${(original.score.final * 100).toFixed(0)}/100 | ${downloads?.toLocaleString() ?? "N/A"} downloads/week`,
					summaries.length > 0 ? `### Top alternatives:\n\n${summaries.join("\n\n---\n\n")}` : "No alternatives found.",
				].join("\n\n");
				return { content: [{ type: "text" as const, text: output }] };
			}
		);

		// Tool 5 — scan_project_deps
		this.server.registerTool(
			"scan_project_deps",
			{
				description: "Audit all dependencies in a package.json. Flags deprecated and low-maintenance packages.",
				inputSchema: {
					package_json: z.string().describe("Full contents of a package.json file"),
				},
			},
			async ({ package_json }) => {
				let parsed: { dependencies?: Record<string, string>; devDependencies?: Record<string, string>; name?: string };
				try {
					parsed = JSON.parse(package_json);
				} catch {
					return { content: [{ type: "text" as const, text: "Invalid JSON. Please paste the full package.json content." }] };
				}
				const names = Object.keys({ ...parsed.dependencies, ...parsed.devDependencies }).slice(0, 20);
				const results = await Promise.all(
					names.map(async (name) => {
						const [npms, registry] = await Promise.all([getNpmsData(name), getNpmRegistry(name)]);
						const latest = registry?.["dist-tags"]?.latest;
						const deprecated = latest ? registry?.versions?.[latest]?.deprecated : undefined;
						return {
							name,
							score: npms?.score.final ?? 0,
							maintenance: npms?.score.detail.maintenance ?? 0,
							deprecated,
							lastPublish: latest && registry?.time?.[latest] ? monthsAgo(registry.time[latest]) : "unknown",
						};
					})
				);
				const deprecated = results.filter((r) => r.deprecated);
				const lowMaintenance = results.filter((r) => !r.deprecated && r.maintenance < 0.4);
				const healthy = results.filter((r) => !r.deprecated && r.maintenance >= 0.4);
				const lines = [
					`## Dependency Audit: ${parsed.name ?? "project"}`,
					`Scanned ${names.length} packages`,
					deprecated.length > 0 ? `\n### ⚠️ Deprecated (${deprecated.length})\n${deprecated.map((r) => `- **${r.name}** — ${r.deprecated}`).join("\n")}` : "",
					lowMaintenance.length > 0 ? `\n### 🔴 Low Maintenance (${lowMaintenance.length})\n${lowMaintenance.map((r) => `- **${r.name}** — maintenance: ${(r.maintenance * 100).toFixed(0)}/100, published: ${r.lastPublish}`).join("\n")}` : "",
					healthy.length > 0 ? `\n### ✅ Healthy (${healthy.length})\n${healthy.map((r) => `- **${r.name}** — score: ${(r.score * 100).toFixed(0)}/100, published: ${r.lastPublish}`).join("\n")}` : "",
				].filter(Boolean).join("\n");
				return { content: [{ type: "text" as const, text: lines }] };
			}
		);
	}
}

// ─── Worker entry ─────────────────────────────────────────────────────────────

export default {
	fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);
		if (url.pathname === "/mcp") {
			return NpmAdvisorMCP.serve("/mcp").fetch(request, env, ctx);
		}
		return new Response("npm-advisor-mcp is live. Connect at /mcp", { status: 200 });
	},
};
