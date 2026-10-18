(function () {
  "use strict";

  // GitHub Pages omits Jekyll's underscore-prefixed include directories from
  // the published site, so use the source fragment from the deployed branch.
  var siteHeaderUrl = "https://raw.githubusercontent.com/nanomsg/nng/gh-pages/_includes/header-nng.html";
  var versionManifestUrl = "/ref/dev/versions.json";
  var siteHeaderPromise;

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
    if (siteHeaderPromise) {
      return siteHeaderPromise;
    }

    if (document.querySelector(".nn-header")) {
      siteHeaderPromise = Promise.resolve(document.querySelector(".nn-header"));
      return siteHeaderPromise;
    }

    siteHeaderPromise = fetch(siteHeaderUrl)
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
        return header;
      })
      .catch(function (error) {
        console.warn(error.message);
        return null;
      });

    return siteHeaderPromise;
  }

  function currentVersionId() {
    var match = window.location.pathname.match(/^\/ref\/([^/]+)(?:\/|$)/);
    return match ? match[1] : null;
  }

  function addLegacyDocumentationBar() {
    var header = document.querySelector(".nn-header");
    var existing = document.querySelector(".nng-docs-menu-bar");

    if (existing) {
      return existing.querySelector(".nng-docs-menu-right");
    }
    if (!header || !document.body.classList.contains("toc2")) {
      return null;
    }

    var bar = document.createElement("nav");
    bar.className = "nng-docs-menu-bar";
    bar.setAttribute("aria-label", "Documentation navigation");

    var left = document.createElement("div");
    left.className = "nng-docs-menu-left";

    var title = document.createElement("div");
    title.className = "nng-docs-menu-title";
    title.textContent = "NNG Reference Manual";

    var right = document.createElement("div");
    right.className = "nng-docs-menu-right";

    bar.appendChild(left);
    bar.appendChild(title);
    bar.appendChild(right);
    header.insertAdjacentElement("afterend", bar);
    return right;
  }

  function addVersionSelector(versions) {
    var toolbar = document.querySelector("#mdbook-menu-bar .right-buttons");
    var legacyMenu = addLegacyDocumentationBar();

    if ((!toolbar && !legacyMenu) || document.querySelector(".nng-version-picker")) {
      return;
    }

    var picker = document.createElement("div");
    picker.className = "nng-version-picker";

    var label = document.createElement("label");
    label.className = "nng-version-label";
    label.htmlFor = "nng-version-select";
    label.textContent = "Version";

    var select = document.createElement("select");
    select.id = "nng-version-select";
    select.setAttribute("aria-label", "Documentation version");

    versions.forEach(function (version) {
      var option = document.createElement("option");
      option.value = version.href;
      option.textContent = version.label;
      option.selected = version.id === currentVersionId();
      select.appendChild(option);
    });

    select.addEventListener("change", function () {
      window.location.assign(select.value);
    });

    picker.appendChild(label);
    picker.appendChild(select);
    if (toolbar) {
      toolbar.insertBefore(picker, toolbar.firstChild);
    } else {
      picker.classList.add("nng-legacy-version-picker");
      legacyMenu.appendChild(picker);
    }
  }

  function addVersionPicker() {
    fetch(versionManifestUrl, { cache: "no-cache" })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("Unable to load documentation versions");
        }
        return response.json();
      })
      .then(function (manifest) {
        if (!manifest || !Array.isArray(manifest.versions)) {
          throw new Error("Documentation version manifest is invalid");
        }
        return addSiteHeader().then(function () {
          addVersionSelector(manifest.versions);
        });
      })
      .catch(function (error) {
        console.warn(error.message);
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      addSiteHeader();
      addVersionPicker();
    });
  } else {
    addSiteHeader();
    addVersionPicker();
  }
}());
