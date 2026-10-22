// The placeholder views for the sections Tasks 15-17 fill. One shape,
// nine names — each says the section ships next, and nothing more: no
// fake data, no fake chrome, nothing that looks finished but is not.

type Stub = () => ReturnType<typeof StubSection>;

export function StubSection({ title }: { title: string }) {
  return (
    <section className="stub-view">
      <h1>{title}</h1>
      <p>This section ships next — it is being built out in the next tasks.</p>
    </section>
  );
}

export const Dashboard: Stub = () => <StubSection title="Dashboard" />;
export const Certificates: Stub = () => <StubSection title="Certificates" />;
export const CertificateNew: Stub = () => <StubSection title="Issue a Certificate" />;
export const CertificateDetail: Stub = () => <StubSection title="Certificate" />;
export const Profiles: Stub = () => <StubSection title="Profiles" />;
export const Cas: Stub = () => <StubSection title="Certificate Authorities" />;
export const Tokens: Stub = () => <StubSection title="API Tokens" />;
export const Audit: Stub = () => <StubSection title="Audit Log" />;
export const Admin: Stub = () => <StubSection title="Admin" />;