import React, { useEffect } from 'react';
import { ScannerInterface } from '@/components/scanner/ScannerInterface';

// Scanner page wrapper. Adds a mount-time cleanup to prevent stale persisted
// scan monitor state (especially start_time) from inflating timers when the
// user returns after a prior scan. We don't have a global "RUNNING" status
// store here, so we conservatively strip any persisted start_time fields.
// This mirrors the intent of resetting if previous state was RUNNING/STARTING.
const Scanner: React.FC = () => {
  useEffect(() => {
    try {
      const keys = Object.keys(localStorage).filter(k => k.startsWith('scan.monitor.state.'));
      for (const k of keys) {
        const raw = localStorage.getItem(k);
        if (!raw) continue;
        try {
          const parsed = JSON.parse(raw);
          // Remove only the timing-related fields so logs/history remain.
          if (parsed && parsed.start_time) {
            delete parsed.start_time;
            localStorage.setItem(k, JSON.stringify(parsed));
          }
        } catch { /* ignore malformed */ }
      }
      // Also clear generic current state key if present
      const generic = 'scan.monitor.state.current';
      const rawGeneric = localStorage.getItem(generic);
      if (rawGeneric) {
        try {
          const parsed = JSON.parse(rawGeneric);
            if (parsed.start_time) {
              delete parsed.start_time;
              localStorage.setItem(generic, JSON.stringify(parsed));
            }
        } catch { /* ignore */ }
      }
    } catch { /* localStorage might be unavailable */ }
  }, []);

  return <ScannerInterface />;
};

export default Scanner;