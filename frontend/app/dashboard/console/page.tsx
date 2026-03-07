"use client";
import { useState } from "react";

export default function ConsolePage() {
  const [tab, setTab] = useState<"scan" | "posture" | "encrypt" | "stats">("scan");
  const [result, setResult] = useState("");
  const [loading, setLoading] = useState(false);
  const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8081";

  async function call(path: string, body?: object) {
    setLoading(true);
    try {
      const r = body
        ? await fetch(`${API}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
        : await fetch(`${API}${path}`);
      setResult(JSON.stringify(await r.json(), null, 2));
    } catch (e: any) { setResult(`Error: ${e.message}`); }
    setLoading(false);
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">DataShield Console</h1>
      <div className="flex gap-2">
        {(["scan", "posture", "encrypt", "stats"] as const).map(t => (
          <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 rounded ${tab === t ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-300"}`}>{t}</button>
        ))}
      </div>
      <div className="bg-gray-800 rounded-lg p-6 space-y-4">
        {tab === "scan" && (
          <button onClick={() => call("/api/v1/datashield/scan", { data_source: "s3://company-data/users", source_type: "s3", deep_scan: true })} className="bg-green-600 px-4 py-2 rounded">Scan Data Source</button>
        )}
        {tab === "posture" && (
          <button onClick={() => call("/api/v1/datashield/posture", { scope: "production" })} className="bg-green-600 px-4 py-2 rounded">Check Posture</button>
        )}
        {tab === "encrypt" && (
          <button onClick={() => call("/api/v1/datashield/encrypt-audit", { data_source: "s3://company-data/users" })} className="bg-green-600 px-4 py-2 rounded">Encryption Audit</button>
        )}
        {tab === "stats" && (
          <button onClick={() => call("/api/v1/datashield/stats")} className="bg-green-600 px-4 py-2 rounded">Get Stats</button>
        )}
      </div>
      {loading && <p className="text-yellow-400">Loading...</p>}
      {result && <pre className="bg-gray-900 p-4 rounded overflow-auto text-sm text-green-400 max-h-96">{result}</pre>}
    </div>
  );
}
