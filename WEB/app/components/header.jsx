"use client";

import React, { useEffect, useState } from "react";
import { ModeToggle } from "./theme-btn";
import { BackgroundBeamsWithCollisionDemo } from "./BackgroundBeamsWithCollisionDemo";
import Image from "next/image";
import { useTheme } from "next-themes";

function Upper() {
  const { theme, systemTheme } = useTheme();
  const [currentTheme, setCurrentTheme] = useState(null);

  useEffect(() => {
    setCurrentTheme(theme === "system" ? systemTheme : theme);
  }, [theme, systemTheme]);

  if (!currentTheme) {
    return null;
  }

  return (
    <div>
      <div className="mx-3 md:mx-16  my-3 px-0">
        <div className="flex items-center justify-between rounded-full">
          <div className="flex items-center gap-1">
          <Image
            src={currentTheme === "dark" ? "/196x196.png" : "/196x196.png"}
            className="rounded-3xl w-16 md:w-24"
            layout="fixed"
            width={100}
            height={100}
            alt="Logo"
          />
          <h1 className="text-5xl bg-blend-color font-semibold">FortiFi</h1>
          </div>
          <ModeToggle />
        </div>
      </div>
      <BackgroundBeamsWithCollisionDemo />
    </div>
  );
}

export default Upper;
