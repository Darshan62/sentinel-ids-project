"use client";

import React, { createContext, useContext, useEffect, useState, useRef } from "react";

interface Packet {
  id: string;
  timestamp: string;
  src_ip: string;
  protocol: string;
  port: string;
  activity: string;
  meaning: string;
  status: "Safe" | "Attack" | "Blocked";
  attackLabel: string;
}

interface Metrics {
  total: number;
  safe: number;
  attack: number;
  blocked: number;
}

interface GlobalStateContextType {
  packets: Packet[];
  metrics: Metrics;
}

const GlobalStateContext = createContext<GlobalStateContextType>({
  packets: [],
  metrics: { total: 0, safe: 0, attack: 0, blocked: 0 }
});

export const useGlobalState = () => useContext(GlobalStateContext);

export default function GlobalStateProvider({ children }: { children: React.ReactNode }) {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [metrics, setMetrics] = useState<Metrics>({ total: 0, safe: 0, attack: 0, blocked: 0 });

  // Refs for 5-second batching
  const bufferRef = useRef<Packet[]>([]);
  const metricsRef = useRef<Metrics>({ total: 0, safe: 0, attack: 0, blocked: 0 });
  const audioRef = useRef<HTMLAudioElement | null>(null);

  useEffect(() => {
    // Initialize audio only on client
    audioRef.current = new Audio("/alert.mpeg");
  }, []);

  useEffect(() => {
    let ws: WebSocket;
    let fallbackInterval: NodeJS.Timeout;

    const connectWs = () => {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${window.location.host}/ws/live-traffic`;
        ws = new WebSocket(wsUrl);
        
        ws.onmessage = (event) => {
          const data: Packet = JSON.parse(event.data);
          bufferRef.current.push(data);
          
          metricsRef.current.total += 1;
          if (data.status === "Safe") {
            metricsRef.current.safe += 1;
          } else if (data.status === "Attack") {
            metricsRef.current.attack += 1;
            // Play audio alert for 2 seconds
            if (audioRef.current) {
              audioRef.current.play().catch(() => {}); // catch browser autoplay blocks
              setTimeout(() => {
                if (audioRef.current) {
                  audioRef.current.pause();
                  audioRef.current.currentTime = 0;
                }
              }, 2000);
            }
          } else if (data.status === "Blocked") {
            metricsRef.current.blocked += 1;
          }
        };

        ws.onclose = () => {
            // Reconnect logic if needed, but for simplicity let's stick to simple setup
            fallbackInterval = setTimeout(connectWs, 3000);
        };
    };

    connectWs();

    // Flush buffer every 5 seconds
    const flushInterval = setInterval(() => {
      if (bufferRef.current.length > 0) {
        const bufferedPackets = [...bufferRef.current];
        bufferRef.current = []; // Clear buffer

        setPackets(prev => [...bufferedPackets.reverse(), ...prev].slice(0, 100)); // Keep up to 100 on screen to avoid lag
        
        // Sync metrics from ref
        setMetrics({ ...metricsRef.current });
      }
    }, 5000);

    return () => {
      if (ws) ws.close();
      clearInterval(flushInterval);
      clearTimeout(fallbackInterval);
    };
  }, []);

  return (
    <GlobalStateContext.Provider value={{ packets, metrics }}>
      {children}
    </GlobalStateContext.Provider>
  );
}
