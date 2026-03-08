import { component$ } from "@builder.io/qwik";
import { QwikCityProvider, RouterOutlet } from "@builder.io/qwik-city";
import { RouterHead } from "./components/router-head/router-head";

import "./global.css";

export default component$(() => {
  return (
    <QwikCityProvider>
      <head>
        <meta charset="utf-8" />
        <RouterHead />
        <script src="/unlock-feedback.js" />
      </head>
      <body lang="en" class="dark">
        <RouterOutlet />
      </body>
    </QwikCityProvider>
  );
});
