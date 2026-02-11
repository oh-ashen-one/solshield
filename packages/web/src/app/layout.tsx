import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SolShield — Security for Vibe-Coded Solana Programs",
  description: "Instant AI-powered security audits for Solana smart contracts. 7,000+ vulnerability patterns from real exploits. Built for the vibe coding era.",
  keywords: ["Solana", "smart contract", "security", "audit", "Anchor", "Rust", "AI", "SolShield", "vibe coding", "AI-generated code"],
  openGraph: {
    title: "SolShield — Security for Vibe-Coded Solana Programs",
    description: "Instant AI-powered security audits for Solana smart contracts. 7,000+ vulnerability patterns from real exploits. Built for the vibe coding era.",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "SolShield — Security for Vibe-Coded Solana Programs",
    description: "AI-generated code ships fast. SolShield catches what your AI missed. 7,000+ patterns. Instant. Free.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
