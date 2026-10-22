// The router map. `/login` is public; everything else lives behind
// <RequireAuth>, which resolves the session store's one boot and bounces
// the unknown to `/login`. Tasks 15-17 replace the stub views with real
// ones — the routes themselves are the contract here.

import type { ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";

import Shell from "./components/Shell";
import { useAuthState } from "./lib/auth";
import Login from "./pages/Login";
import {
  Admin,
  Audit,
  Cas,
  CertificateDetail,
  CertificateNew,
  Certificates,
  Dashboard,
  Profiles,
  Tokens,
} from "./pages/Stub";

/** The guard: unauthenticated → /login (replace, so a back button never
 * re-enters the guarded shell); booting → a quiet "checking" pane instead
 * of a redirect race against the boot. */
function RequireAuth({ children }: { children: ReactNode }) {
  const state = useAuthState();
  if (state.status === "booting") {
    return (
      <main className="boot-screen">
        <p>Checking your session…</p>
      </main>
    );
  }
  if (state.status === "unauthenticated") {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <Shell />
          </RequireAuth>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="certificates" element={<Certificates />} />
        <Route path="certificates/new" element={<CertificateNew />} />
        <Route path="certificates/:id" element={<CertificateDetail />} />
        <Route path="profiles" element={<Profiles />} />
        <Route path="cas" element={<Cas />} />
        <Route path="tokens" element={<Tokens />} />
        <Route path="audit" element={<Audit />} />
        <Route path="admin" element={<Admin />} />
      </Route>
      {/* Everything else is the dashboard: a deep link that outlived its
          day lands somewhere real, never in a dead end. */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}