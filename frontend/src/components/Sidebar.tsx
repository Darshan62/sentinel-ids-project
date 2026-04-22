import React from "react";
import { Shield, Activity } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

export default function Sidebar() {
  const pathname = usePathname();

  const links = [
    { name: "Overview", path: "/", icon: <Activity size={18} /> },
  ];

  return (
    <aside className="w-64 bg-surface-low border-r border-surface-high/50 p-6 flex flex-col gap-8 flex-shrink-0 min-h-screen">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-surface-highest flex items-center justify-center text-primary">
          <Shield size={20} />
        </div>
        <div>
          <p className="font-mono text-xs font-bold uppercase tracking-widest text-text-primary m-0">NODE-01</p>
          <p className="font-mono text-[10px] text-text-secondary m-0">US-EAST-SHIELD</p>
        </div>
      </div>
      <nav className="flex flex-col gap-2">
        {links.map((link) => {
          const isActive = pathname === link.path;
          return (
            <Link key={link.name} href={link.path} className={`flex items-center gap-4 px-4 py-3 transition-colors ${isActive ? 'bg-gradient-to-r from-primary/10 to-transparent text-primary border-l-4 border-primary' : 'text-text-primary/40 hover:text-text-primary/70 border-l-4 border-transparent'}`}>
              {link.icon}
              <span className="font-mono text-xs font-bold uppercase tracking-widest">{link.name}</span>
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
