import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { MainLayout } from "@/components/layout/MainLayout";
import Dashboard from "./pages/Dashboard";
import Scanner from "./pages/Scanner";
import Vulnerabilities from "./pages/Vulnerabilities";
import Reports from "./pages/Reports";
import { AIAnalysis } from "./pages/AIAnalysis";
import { OASTManager } from "./components/scanner/OASTManager";
import { Analytics } from "./components/analytics";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={
            <MainLayout>
              <Dashboard />
            </MainLayout>
          } />
          <Route path="/scanner" element={
            <MainLayout>
              <Scanner />
            </MainLayout>
          } />
          <Route path="/vulnerabilities" element={
            <MainLayout>
              <Vulnerabilities />
            </MainLayout>
          } />
          <Route path="/reports" element={
            <MainLayout>
              <Reports />
            </MainLayout>
          } />
          <Route path="/ai" element={
            <MainLayout>
              <AIAnalysis />
            </MainLayout>
          } />
          <Route path="/oast" element={
            <MainLayout>
              <OASTManager />
            </MainLayout>
          } />
          <Route path="/analytics" element={
            <MainLayout>
              <Analytics />
            </MainLayout>
          } />
          <Route path="/settings" element={
            <MainLayout>
              <div className="p-6">
                <h1 className="text-3xl font-bold text-foreground">Settings</h1>
                <p className="text-muted-foreground">Coming soon...</p>
              </div>
            </MainLayout>
          } />
          {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
