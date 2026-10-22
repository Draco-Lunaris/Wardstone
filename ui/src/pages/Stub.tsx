// The placeholder that remains: Admin ships in Task 17. One shape — it
// says the section ships next, and nothing more: no fake data, no fake
// chrome, nothing that looks finished but is not. (The certificate views
// are real since Task 15; the dashboard, profiles, CAs, tokens, and
// audit views are real since Task 16.)

type Stub = () => ReturnType<typeof StubSection>;

export function StubSection({ title }: { title: string }) {
  return (
    <section className="stub-view">
      <h1>{title}</h1>
      <p>This section ships next — it is being built out in the next tasks.</p>
    </section>
  );
}

export const Admin: Stub = () => <StubSection title="Admin" />;