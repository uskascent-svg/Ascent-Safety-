import type { Metadata, Viewport } from "next";

import Footer from "@/components/Footer";
import Header from "@/components/Header";
import Providers from "@/components/Providers";

import "./globals.css";

export const metadata: Metadata = {
  title: "Ascent Safety — Detect. Prevent. Protect.",
  description:
    "Ascent Safety helps you detect, understand, and prevent cyber threats with security event monitoring and analysis.",
};

export const viewport: Viewport = { themeColor: "#05070d" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen font-sans antialiased">
        <Providers>
          <Header />
          <div className="flex min-h-[calc(100vh-60px)] flex-col lg:pl-[248px]">
            <main className="flex-1">{children}</main>
            <Footer />
          </div>
        </Providers>
      </body>
    </html>
  );
}
