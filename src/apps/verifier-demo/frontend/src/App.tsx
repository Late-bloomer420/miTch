import { SplitScreen } from './components/SplitScreen';

const configuredBackendUrl = (import.meta as unknown as Record<string, Record<string, string>>).env
    ?.VITE_VERIFIER_BACKEND_URL;
const backendUrl = configuredBackendUrl || `http://${window.location.hostname}:3004`;

export default function App() {
    return <SplitScreen backendUrl={backendUrl} />;
}
