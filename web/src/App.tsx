import { Routes, Route, Navigate, useParams } from 'react-router';
import { Layout } from './components/Layout';
import { Home } from './pages/Home';
import { WizardPage } from './pages/wizard/WizardPage';
import { SummaryPage } from './pages/SummaryPage';
import { BuildPage } from './pages/BuildPage';
import { ResultsPage } from './pages/ResultsPage';
import { SettingsPage } from './pages/SettingsPage';
import { DashboardPage } from './pages/DashboardPage';
import SecurityAcrossAppsPage from './pages/SecurityAcrossAppsPage';
import { VerifyPage } from './pages/VerifyPage';
import SecurityPage from './pages/SecurityPage';
import { UploadPage } from './pages/UploadPage';
import { RefinePage } from './pages/RefinePage';
import { NotFoundPage } from './pages/NotFoundPage';

function WizardIndexRedirect() {
  const { id } = useParams();
  return <Navigate to={`/projects/${id}/wizard/about`} replace />;
}

export function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/projects/:id/wizard" element={<WizardIndexRedirect />} />
        <Route path="/projects/:id/wizard/:step" element={<WizardPage />} />
        <Route path="/projects/:id/refine" element={<RefinePage />} />
        <Route path="/projects/:id/summary" element={<SummaryPage />} />
        <Route path="/projects/:id/build" element={<BuildPage />} />
        <Route path="/projects/:id/results" element={<ResultsPage />} />
        <Route path="/projects/:id/verify" element={<VerifyPage />} />
        <Route path="/projects/:id/security" element={<SecurityPage />} />
        <Route path="/projects/:id/upload" element={<UploadPage />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/security" element={<SecurityAcrossAppsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Layout>
  );
}
