
import React from 'react';

const Header: React.FC = () => {
  return (
    <header className="flex items-center justify-between pb-4 border-b border-gray-700">
      <div className="flex items-center gap-3">
         <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="w-8 h-8 text-cyan-400">
          <path fillRule="evenodd" d="M12.516 2.17a.75.75 0 0 0-1.032 0L2.22 11.127c-.431.42.164 1.154.697 1.013l4.52-.904a.75.75 0 0 1 .65.263l3.355 4.193-3.086 3.086a.75.75 0 0 0 0 1.06l.53.53a.75.75 0 0 0 1.06 0l3.086-3.086 5.254 2.102a.75.75 0 0 0 .96-.349l2.25-4.5a.75.75 0 0 0-.236-.883l-2.435-1.826 4.194-3.355a.75.75 0 0 1 .263-.65l-.904-4.52c-.14-.533-.876-.266-1.013.164L12.516 2.17Z" clipRule="evenodd" />
        </svg>
        <h1 className="text-2xl sm:text-3xl font-bold text-gray-100 tracking-tight">
          AI-Powered Vulnerability Report
        </h1>
      </div>
    </header>
  );
};

export default Header;
