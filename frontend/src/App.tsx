import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Analytics } from './routes/Analytics'
import { Fleet } from './routes/Fleet'
import { IncidentDetail } from './routes/IncidentDetail'
import { IncidentList } from './routes/IncidentList'
import { Overview } from './routes/Overview'
import { ThreatMonitor } from './routes/ThreatMonitor'

const queryClient = new QueryClient()

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="incidents" element={<IncidentList />} />
            <Route path="incidents/:incidentId" element={<IncidentDetail />} />
            <Route path="fleet" element={<Fleet />} />
            <Route path="threat-monitor" element={<ThreatMonitor />} />
            <Route path="analytics" element={<Analytics />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
