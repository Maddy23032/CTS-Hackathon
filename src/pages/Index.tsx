import React from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { DashboardOverview } from '@/components/dashboard/DashboardOverview';

const Index = () => {
  return (
    <MainLayout>
      <DashboardOverview />
    </MainLayout>
  );
};

export default Index;
