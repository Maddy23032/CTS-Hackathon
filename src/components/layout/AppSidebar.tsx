import React from 'react';
import { 
  Shield, 
  Search, 
  Activity, 
  FileText, 
  Settings, 
  Brain,
  Target,
  BarChart3,
  AlertTriangle,
  Globe
} from 'lucide-react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from '@/components/ui/sidebar';

const navigationItems = [
  { title: 'Dashboard', url: '/', icon: Activity },
  { title: 'Scanner', url: '/scanner', icon: Search },
  { title: 'Vulnerabilities', url: '/vulnerabilities', icon: AlertTriangle },
  { title: 'Reports', url: '/reports', icon: FileText },
  { title: 'AI Analysis', url: '/ai', icon: Brain },
  { title: 'Targets', url: '/targets', icon: Target },
  { title: 'OAST', url: '/oast', icon: Globe },
  { title: 'Analytics', url: '/analytics', icon: BarChart3 },
  { title: 'Settings', url: '/settings', icon: Settings },
];

export function AppSidebar() {
  const { state } = useSidebar();
  const location = useLocation();
  const currentPath = location.pathname;
  const isCollapsed = state === 'collapsed';

  const isActive = (path: string) => currentPath === path;
  const getNavClasses = (path: string) =>
    isActive(path) 
      ? "bg-primary text-primary-foreground shadow-glow-primary" 
      : "hover:bg-secondary/50 hover:text-foreground";

  return (
    <Sidebar className={isCollapsed ? "w-16" : "w-64"} collapsible="icon">
      <SidebarContent className="bg-background border-r border-border">
        {/* Logo/Brand */}
        <div className="p-4 border-b border-border">
          <div className="flex items-center gap-2">
            <div className="p-2 bg-gradient-primary rounded-lg shadow-glow-primary">
              <Shield className="h-6 w-6 text-primary-foreground" />
            </div>
            {!isCollapsed && (
              <div>
                <h1 className="text-xl font-bold text-foreground">VulnPy</h1>
                <p className="text-sm text-muted-foreground">Security Scanner</p>
              </div>
            )}
          </div>
        </div>

        <SidebarGroup>
          <SidebarGroupLabel>Navigation</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {navigationItems.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton asChild>
                    <NavLink 
                      to={item.url} 
                      className={`flex items-center gap-3 p-3 rounded-lg transition-all duration-200 ${getNavClasses(item.url)}`}
                    >
                      <item.icon className="h-5 w-5 flex-shrink-0" />
                      {!isCollapsed && <span className="font-medium">{item.title}</span>}
                    </NavLink>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Status Section */}
        <div className="mt-auto p-4 border-t border-border">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-status-success rounded-full animate-pulse-glow"></div>
            {!isCollapsed && (
              <span className="text-sm text-status-success font-medium">System Online</span>
            )}
          </div>
        </div>
      </SidebarContent>
    </Sidebar>
  );
}