import React from 'react';
import { 
  SidebarTrigger,
  useSidebar 
} from '@/components/ui/sidebar';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
  Bell, 
  Play, 
  Pause, 
  Square,
  Wifi,
  WifiOff
} from 'lucide-react';

export function TopBar() {
  const [isScanning, setIsScanning] = React.useState(false);
  const [isConnected, setIsConnected] = React.useState(true);

  return (
    <header className="flex items-center justify-between p-4 border-b border-border bg-card">
      <div className="flex items-center gap-4">
        <SidebarTrigger className="text-foreground" />
        
        {/* Current Target Display */}
        <div className="flex items-center gap-3">
          <span className="text-sm text-muted-foreground">Target:</span>
          <Badge variant="outline" className="font-mono">
            https://example.com
          </Badge>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Scan Controls */}
        <div className="flex items-center gap-2">
          {!isScanning ? (
            <Button 
              variant="scanner" 
              size="sm"
              onClick={() => setIsScanning(true)}
            >
              <Play className="h-4 w-4" />
              Start Scan
            </Button>
          ) : (
            <div className="flex gap-2">
              <Button 
                variant="warning" 
                size="sm"
                onClick={() => setIsScanning(false)}
              >
                <Pause className="h-4 w-4" />
                Pause
              </Button>
              <Button 
                variant="critical" 
                size="sm"
                onClick={() => setIsScanning(false)}
              >
                <Square className="h-4 w-4" />
                Stop
              </Button>
            </div>
          )}
        </div>

        {/* Status Indicators */}
        <div className="flex items-center gap-3">
          {/* Connection Status */}
          <div className="flex items-center gap-2">
            {isConnected ? (
              <Wifi className="h-4 w-4 text-status-success" />
            ) : (
              <WifiOff className="h-4 w-4 text-status-error" />
            )}
            <span className="text-sm text-muted-foreground">
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>

          {/* Notifications */}
          <Button variant="ghost" size="icon">
            <Bell className="h-4 w-4" />
          </Button>

          {/* Scanning Status */}
          {isScanning && (
            <Badge className="bg-status-scanning text-foreground animate-pulse-glow">
              Scanning...
            </Badge>
          )}
        </div>
      </div>
    </header>
  );
}