import Link from "next/link";

export default function LandingPage() {
  return (
    <main className="min-h-screen bg-gradient-to-b from-gray-950 to-gray-900 text-white">
      <nav className="flex items-center justify-between px-8 py-4 border-b border-gray-800">
        <span className="text-xl font-bold">ALICE DataShield</span>
        <div className="flex gap-4">
          <Link href="/dashboard" className="bg-blue-600 px-4 py-2 rounded hover:bg-blue-500">Dashboard</Link>
        </div>
      </nav>
      <section className="max-w-4xl mx-auto px-8 py-24 text-center space-y-8">
        <h1 className="text-5xl font-extrabold">Data Security Posture Management</h1>
        <p className="text-xl text-gray-400">Automated sensitive data discovery, classification, and security posture scoring. PII/PCI/PHI detection with encryption audit and compliance mapping.</p>
        <div className="flex justify-center gap-4">
          <Link href="/dashboard" className="bg-blue-600 px-8 py-3 rounded-lg text-lg hover:bg-blue-500">Get Started</Link>
        </div>
      </section>
      <section className="max-w-5xl mx-auto px-8 py-16 grid md:grid-cols-3 gap-8">
        {[
          { title: "Data Discovery", desc: "Scan S3, databases, and file systems to discover and classify sensitive data. PII, PCI, PHI auto-detection." },
          { title: "Posture Scoring", desc: "Real-time security posture scoring with risk-level assessment, findings breakdown, and actionable recommendations." },
          { title: "Encryption Audit", desc: "Verify encryption at rest and in transit. Key rotation tracking with GDPR, HIPAA, SOC2 compliance mapping." },
        ].map((f) => (
          <div key={f.title} className="bg-gray-800 rounded-lg p-6">
            <h3 className="text-lg font-bold mb-2">{f.title}</h3>
            <p className="text-gray-400">{f.desc}</p>
          </div>
        ))}
      </section>
    </main>
  );
}
