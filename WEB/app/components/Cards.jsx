"use client";
import Image from "next/image";
import React from "react";
import { Carousel, Card } from "@/app/components/ui/apple-cards-carousel";
import { FileUploadDemo } from "./FileUploadDemo";
import { URLScanDemo } from "./URLScanDemo";
import { SmsScanDemo } from "./SmsScanDemo";
import { Documentation } from "./Documentation";


export function Cards() {
  const cards = data.map((card, index) => (
    <Card key={card.src} card={card} index={index} />
  ));

  return (
    (<div className="relative w-full h-full py-20 border rounded-t-3xl -mt-5 z-10 bg-white dark:bg-neutral-900 ">
      <h2
        className="max-w-7xl pl-4 mx-auto text-xl md:text-5xl font-bold text-neutral-800 dark:text-neutral-200 font-sans">
        Keep your Device Secure
      </h2>
      <Carousel items={cards} />
    </div>)
  );
}

const FileScan = () => {
  return (
    <FileUploadDemo/>
  );
};

const URLScan = () => {
  return (
    <URLScanDemo/>
  );
};
const SmsScan = () => {
  return (
    <SmsScanDemo/>
  );
};
const Content = () => {
  return (
    <Documentation/>
  );
};
const data = [
  {
    category: "File Scanner",
    title: "Advance Malware Scanner with AI.",
    src:"https://i.postimg.cc/kM6Jkvty/matrix-5361690-1920.png",
    content: <FileScan />,
    
  },
  {
    category: "URL Scanner",
    title: "Malicious Website Scanner.",
    src: "https://i.postimg.cc/g2YK0DRC/magnifying-glass-with-scan-search-concept-state-art-electronic-technology-background-167862-7155.jpg",
    content: <URLScan />,
  },
  {
    category: "SMS Scanner",
    title: "Phishing Messages detector",
    src: "https://i.postimg.cc/mgG3K6L3/shutterstock-2253099797-1440x810.jpg",
    content: <SmsScan />,
  },

  {
    category: "Documentations",
    title: "Know more about the technology.",
    src: "https://i.postimg.cc/KcDkYyNY/Wavy-Bus-33-Single-12.jpg",
    content: <Content />,
  },


];
