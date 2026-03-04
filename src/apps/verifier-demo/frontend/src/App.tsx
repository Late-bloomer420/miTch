import { SplitScreen } from './components/SplitScreen';

// Derive backend URL from current hostname so LAN access works automatically.
// When opened via http://192.168.0.100:5175, backend becomes http://192.168.0.100:3004
const backendUrl = `http://${window.location.hostname}:3004`;

export default function App() {
    return <SplitScreen backendUrl={backendUrl} />;
}
