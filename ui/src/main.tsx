import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import App from "./App";
import { SessionProvider } from "./lib/auth";
import "./index.css";

// ws-web serves the SPA from the instance root and answers deep links
// with the document, so BrowserRouter (history-based) is safe; the
// session boots once inside the provider before the guard decides.
createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <BrowserRouter>
      <SessionProvider>
        <App />
      </SessionProvider>
    </BrowserRouter>
  </StrictMode>,
);