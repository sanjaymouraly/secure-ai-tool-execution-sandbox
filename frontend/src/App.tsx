import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Spinner } from "./components/ui";
import { useAuth } from "./context/AuthContext";
import { LoginPage } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { AgentPage } from "./pages/Agent";
import { WorkspacePage } from "./pages/Workspace";
import { ToolsPage } from "./pages/Tools";
import { PoliciesPage } from "./pages/Policies";
import { ApprovalsPage } from "./pages/Approvals";
import { ExecutionsPage } from "./pages/Executions";
import { SandboxPage } from "./pages/Sandbox";
import { AttackLabPage } from "./pages/AttackLab";
import { AuditPage } from "./pages/Audit";
import { ProvidersPage } from "./pages/Providers";
import { SettingsPage } from "./pages/Settings";

export default function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-surface">
        <Spinner label="Starting the control plane" />
      </div>
    );
  }

  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route element={<Layout />}>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/agent" element={<AgentPage />} />
        <Route path="/workspace" element={<WorkspacePage />} />
        <Route path="/tools" element={<ToolsPage />} />
        <Route path="/policies" element={<PoliciesPage />} />
        <Route path="/approvals" element={<ApprovalsPage />} />
        <Route path="/executions" element={<ExecutionsPage />} />
        <Route path="/sandbox" element={<SandboxPage />} />
        <Route path="/attack-lab" element={<AttackLabPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/providers" element={<ProvidersPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
