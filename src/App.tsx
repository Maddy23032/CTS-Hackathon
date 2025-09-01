import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { MainLayout } from "@/components/layout/MainLayout";
import Dashboard from "./pages/Dashboard";
import Scanner from "./pages/Scanner";
import Vulnerabilities from "./pages/Vulnerabilities";
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
              <div className="p-6">
                <h1 className="text-3xl font-bold text-foreground">Reports</h1>
                <p className="text-muted-foreground">Coming soon...</p>
              </div>
            </MainLayout>
          } />
          <Route path="/ai" element={
            <MainLayout>
              <div className="p-6">
                <h1 className="text-3xl font-bold text-foreground">AI Analysis</h1>
                <p className="text-muted-foreground">Coming soon...</p>
              </div>
            </MainLayout>
          } />
          <Route path="/targets" element={
            <MainLayout>
              <div className="p-6">
                <h1 className="text-3xl font-bold text-foreground">Target Management</h1>
                <p className="text-muted-foreground">Coming soon...</p>
              </div>
            </MainLayout>
          } />
          <Route path="/analytics" element={
            <MainLayout>
              <div className="p-6">
                <h1 className="text-3xl font-bold text-foreground">Analytics</h1>
                <p className="text-muted-foreground">Coming soon...</p>
              </div>
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
