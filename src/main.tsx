import React from "react";
import ReactDOM from "react-dom/client";

import App from "./App";
import { ThemeProvider } from "@/components/theme-provider";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import "./index.css";

/**
 * Block the browser context menu in production so a stray right-click cannot
 * offer to copy or inspect a revealed secret. Left enabled in development
 * because devtools are useful there.
 */
if (!import.meta.env.DEV) {
  document.addEventListener("contextmenu", (event) => event.preventDefault());
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <ThemeProvider>
      <TooltipProvider delayDuration={300}>
        <App />
        <Toaster position="bottom-right" richColors closeButton />
      </TooltipProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
