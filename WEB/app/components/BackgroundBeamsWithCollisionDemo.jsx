import React from "react";
import { BackgroundBeamsWithCollision } from "@/app/components/ui/background-beams-with-collision";

export function BackgroundBeamsWithCollisionDemo() {
  return (
    (<BackgroundBeamsWithCollision>
      <div>
      <h2
        className="text-2xl relative  md:text-4xl lg:text-7xl font-bold text-center text-black dark:text-white font-sans tracking-tight">
        Know the power of {" "}
        <div
          className="relative mx-auto inline-block w-max [filter:drop-shadow(0px_1px_3px_rgba(27,_37,_80,_0.14))]">
          <div
            className="absolute left-0 top-[1px] bg-clip-text bg-no-repeat text-transparent bg-gradient-to-r py-4 from-purple-500 via-violet-500 to-pink-500 [text-shadow:0_0_rgba(0,0,0,0.1)]">
            <span className="">VAULT - 7.</span>
          </div>
          <div
            className="relative bg-clip-text text-transparent bg-no-repeat bg-gradient-to-r from-purple-500 via-violet-500 to-pink-500 py-4">
            <span className="">VAULT - 7.</span>
          </div>
        </div>
      </h2>
      <h1 className="text-2xl relative md:text-1xl lg:text-4xl font-bold text-center text-black dark:text-white font-sans tracking-tight pb-4">
  <a
    href="/app.apk" 
    download
    className="cursor-pointer hover:text-blue-500 transition duration-300"
  >
    Download the App
  </a>
</h1>


      </div>
    </BackgroundBeamsWithCollision>)
  );
}
