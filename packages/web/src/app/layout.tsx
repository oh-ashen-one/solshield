import type { Metadata } from "next";
import { Inter, Space_Grotesk, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const spaceGrotesk = Space_Grotesk({
  variable: "--font-space",
  subsets: ["latin"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
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
    <html lang="en" className="scroll-smooth">
      <body
        className={`${inter.variable} ${spaceGrotesk.variable} ${jetbrainsMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
