import { Route, Router, Switch } from "wouter";
import { useHashLocation } from "wouter/use-hash-location";
import { Shell } from "./components/Shell";
import { ErrorBoundary, Toasts } from "./components/ui";
import Overview from "./pages/Overview";
import Ingest from "./pages/Ingest";
import { DeviceDetail, DeviceList } from "./pages/Devices";
import Findings from "./pages/Findings";
import Frameworks from "./pages/Frameworks";
import Training from "./pages/Training";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import Help from "./pages/Help";
import NotFound from "./pages/NotFound";

export default function App() {
  return (
    <Router hook={useHashLocation}>
      <ErrorBoundary>
        <Shell>
          <Switch>
            <Route path="/" component={Overview} />
            <Route path="/ingest" component={Ingest} />
            <Route path="/devices" component={DeviceList} />
            <Route path="/devices/:id" component={DeviceDetail} />
            <Route path="/findings" component={Findings} />
            <Route path="/frameworks" component={Frameworks} />
            <Route path="/training" component={Training} />
            <Route path="/reports" component={Reports} />
            <Route path="/help" component={Help} />
            <Route path="/settings" component={Settings} />
            <Route component={NotFound} />
          </Switch>
        </Shell>
      </ErrorBoundary>
      <Toasts />
    </Router>
  );
}
