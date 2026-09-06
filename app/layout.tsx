import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PolicyGuard — GenLayer Policy Compliance",
  description:
    "Version human-written policies, authenticate evidence, and authorize organizational actions only after a finalized GenLayer compliance verdict.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
