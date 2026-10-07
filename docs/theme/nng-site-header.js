(function () {
  "use strict";

  function addSiteHeader() {
    if (document.getElementById("nng-site-header")) {
      return;
    }

    document.body.insertAdjacentHTML("afterbegin", `
      <header id="nng-site-header">
        <nav class="nng-site-header-inner" aria-label="NNG site navigation">
          <a class="nng-site-brand" href="https://nng.nanomsg.org/" aria-label="NNG home">
            <img src="https://nng.nanomsg.org/assets/image/NNg-white.png" width="54" height="36" alt="NNG">
          </a>
          <button class="nng-site-menu-toggle" type="button" aria-label="Toggle site navigation" aria-expanded="false" aria-controls="nng-site-links">
            <svg aria-hidden="true" viewBox="0 0 448 512"><path d="M0 96c0-17.7 14.3-32 32-32h384c17.7 0 32 14.3 32 32s-14.3 32-32 32H32c-17.7 0-32-14.3-32-32zm0 160c0-17.7 14.3-32 32-32h384c17.7 0 32 14.3 32 32s-14.3 32-32 32H32c-17.7 0-32-14.3-32-32zm448 160c0 17.7-14.3 32-32 32H32c-17.7 0-32-14.3-32-32s14.3-32 32-32h384c17.7 0 32 14.3 32 32z"/></svg>
          </button>
          <div id="nng-site-links" class="nng-site-links">
            <a class="nng-site-link" href="https://nng.nanomsg.org/man/">
              <svg aria-hidden="true" viewBox="0 0 512 512"><path d="M96 0C43 0 0 43 0 96v320c0 53 43 96 96 96h320c53 0 96-43 96-96V96c0-53-43-96-96-96H96zm48 144c0-8.8 7.2-16 16-16h192c8.8 0 16 7.2 16 16v16c0 8.8-7.2 16-16 16H160c-8.8 0-16-7.2-16-16v-16zm0 96c0-8.8 7.2-16 16-16h192c8.8 0 16 7.2 16 16v16c0 8.8-7.2 16-16 16H160c-8.8 0-16-7.2-16-16v-16zm0 96c0-8.8 7.2-16 16-16h128c8.8 0 16 7.2 16 16v16c0 8.8-7.2 16-16 16H160c-8.8 0-16-7.2-16-16v-16z"/></svg>
              <span>Manual</span>
            </a>
            <a class="nng-site-link" href="https://discord.gg/Xnac6b9">
              <svg aria-hidden="true" viewBox="0 0 640 512"><path d="M524.5 69.8a1.5 1.5 0 0 0-.8-.7A485.1 485.1 0 0 0 404.1 32a1.8 1.8 0 0 0-1.9.9 337.5 337.5 0 0 0-14.9 30.6 447.8 447.8 0 0 0-134.4 0A309.5 309.5 0 0 0 237.6 33a1.9 1.9 0 0 0-1.9-.9 483.7 483.7 0 0 0-119.6 37.1 1.7 1.7 0 0 0-.8.7C39.6 183.6 18.5 294.7 28.9 404.5a2 2 0 0 0 .8 1.4 487.7 487.7 0 0 0 146.7 74.1 1.9 1.9 0 0 0 2.1-.7 348.2 348.2 0 0 0 30-48.8 1.9 1.9 0 0 0-1-2.6 321.2 321.2 0 0 1-45.9-21.8 1.9 1.9 0 0 1-.2-3.1c3.1-2.3 6.1-4.7 9-7.1a1.8 1.8 0 0 1 1.9-.3c96.2 44 200.5 44 295.5 0a1.8 1.8 0 0 1 1.9.3c2.9 2.4 5.9 4.8 9 7.1a1.9 1.9 0 0 1-.2 3.1 301.4 301.4 0 0 1-45.9 21.8 1.9 1.9 0 0 0-1 2.6 391.1 391.1 0 0 0 30 48.8 1.9 1.9 0 0 0 2.1.7 486 486 0 0 0 146.7-74.1 1.9 1.9 0 0 0 .8-1.4c12.4-127.6-21.1-237.7-81.9-334.6zM218.1 337.6c-28.9 0-52.7-26.4-52.7-58.8s23.4-58.8 52.7-58.8 53.2 26.7 52.7 58.8c0 32.4-23.4 58.8-52.7 58.8zm193.8 0c-28.9 0-52.7-26.4-52.7-58.8s23.4-58.8 52.7-58.8 53.2 26.7 52.7 58.8c0 32.4-23.4 58.8-52.7 58.8z"/></svg>
              <span>Discord</span>
            </a>
            <a class="nng-site-link" href="https://github.com/nanomsg/nng">
              <svg aria-hidden="true" viewBox="0 0 496 512"><path d="M165.9 397.4c0 2-2.3 3.6-5.2 3.6-3.3.3-5.6-1.3-5.6-3.6 0-2 2.3-3.6 5.2-3.6 3-.3 5.6 1.3 5.6 3.6zm-31.1-4.5c-.7 2 1.3 4.3 4.3 4.9 2.6 1 5.6 0 6.2-2s-1.3-4.3-4.3-5.2c-2.6-.7-5.5.3-6.2 2.3zm44.2-1.7c-2.9.7-4.9 2.6-4.6 4.9.3 2 2.9 3.3 5.9 2.6 2.9-.7 4.9-2.6 4.6-4.6-.3-1.9-3-3.2-5.9-2.9zM244.8 8C106.1 8 0 113.3 0 252c0 110.9 69.8 205.8 169.5 239.2 12.8 2.3 17.3-5.6 17.3-12.1 0-6.2-.3-40.4-.3-61.4 0 0-70 15-84.7-29.8 0 0-11.4-29.1-27.8-36.6 0 0-22.9-15.7 1.6-15.4 0 0 24.9 2 38.6 25.8 21.9 38.6 58.6 27.5 72.9 20.9 2.3-16 8.8-27.1 16-33.7-55.9-6.2-112.3-14.3-112.3-110.5 0-27.5 7.6-41.3 23.6-58.9-2.6-6.5-11.1-33.3 2.6-67.9 20.9-6.5 69 27 69 27 20-5.6 41.5-8.5 62.8-8.5s42.8 2.9 62.8 8.5c0 0 48.1-33.6 69-27 13.7 34.7 5.2 61.4 2.6 67.9 16 17.7 23.6 31.5 23.6 58.9 0 96.5-58.9 104.2-114.8 110.5 9.2 7.9 17 22.9 17 46.4 0 33.7-.3 75.4-.3 83.6 0 6.5 4.6 14.4 17.3 12.1C428.2 457.8 496 362.9 496 252 496 113.3 383.5 8 244.8 8z"/></svg>
              <span>GitHub</span>
            </a>
            <a class="nng-site-link nng-site-download" href="https://github.com/nanomsg/nng/releases">
              <svg aria-hidden="true" viewBox="0 0 512 512"><path d="M288 32c0-17.7-14.3-32-32-32s-32 14.3-32 32v242.7l-73.4-73.4c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3l128 128c12.5 12.5 32.8 12.5 45.3 0l128-128c12.5-12.5 12.5-32.8 0-45.3s-32.8-12.5-45.3 0L288 274.7V32zM64 352c-35.3 0-64 28.7-64 64v32c0 35.3 28.7 64 64 64h384c35.3 0 64-28.7 64-64v-32c0-35.3-28.7-64-64-64H64zm304 72c13.3 0 24 10.7 24 24s-10.7 24-24 24-24-10.7-24-24 10.7-24 24-24z"/></svg>
              <span>Download</span>
            </a>
          </div>
        </nav>
      </header>`);

    var toggle = document.querySelector(".nng-site-menu-toggle");
    var links = document.getElementById("nng-site-links");
    toggle.addEventListener("click", function () {
      var isOpen = links.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", String(isOpen));
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", addSiteHeader);
  } else {
    addSiteHeader();
  }
}());
