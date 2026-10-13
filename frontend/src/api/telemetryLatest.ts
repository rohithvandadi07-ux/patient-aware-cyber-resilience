import type { TelemetryReading } from './types'

/**
 * The most recent recorded `TelemetryReading` per device, from the real
 * `TelemetryStore` (`GET /telemetry`, no `device_id` filter -- every
 * reading recorded so far). A device absent from the map has had no
 * telemetry recorded for it yet (the store is in-memory and only
 * `/detections/run-scenario` writes into it today) -- that is shown as
 * "no telemetry yet," never a fabricated reading.
 */
export function latestReadingByDevice(readings: TelemetryReading[]): Map<string, TelemetryReading> {
  const latest = new Map<string, TelemetryReading>()

  for (const reading of readings) {
    const existing = latest.get(reading.device_id)
    if (!existing || new Date(reading.timestamp).getTime() >= new Date(existing.timestamp).getTime()) {
      latest.set(reading.device_id, reading)
    }
  }

  return latest
}
