(function () {
  "use strict";

  // GitHub Pages omits Jekyll's underscore-prefixed include directories from
  // the published site, so use the source fragment from the deployed branch.
  var siteHeaderUrl = "https://raw.githubusercontent.com/nanomsg/nng/gh-pages/_includes/header-nng.html";

  function enableMenuToggle(header) {
    var toggle = header.querySelector(".navbar-burger");
    var menu = header.querySelector("#navbarBasicExample");

    if (!toggle || !menu) {
      return;
    }

    toggle.addEventListener("click", function () {
      var isOpen = menu.classList.toggle("is-active");
      toggle.classList.toggle("is-active", isOpen);
      toggle.setAttribute("aria-expanded", String(isOpen));
    });
  }

  function addSiteHeader() {
    if (document.querySelector(".nn-header")) {
      return;
    }

    fetch(siteHeaderUrl)
      .then(function (response) {
        if (!response.ok) {
          throw new Error("Unable to load the NNG site header");
        }
        return response.text();
      })
      .then(function (markup) {
        var documentFragment = new DOMParser().parseFromString(markup, "text/html");
        var header = documentFragment.querySelector(".nn-header");

        if (!header || document.querySelector(".nn-header")) {
          return;
        }

        // The shared fragment contains its own initialization script. The
        // script is deliberately replaced with the local initializer above.
        header.querySelectorAll("script").forEach(function (script) {
          script.remove();
        });
        header.querySelectorAll("[href^='/'], [src^='/']").forEach(function (element) {
          var attribute = element.hasAttribute("href") ? "href" : "src";
          element.setAttribute(attribute, "https://nng.nanomsg.org" + element.getAttribute(attribute));
        });
        document.body.insertAdjacentElement("afterbegin", header);
        enableMenuToggle(header);
      })
      .catch(function (error) {
        console.warn(error.message);
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", addSiteHeader);
  } else {
    addSiteHeader();
  }
}());
