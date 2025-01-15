// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded affix "><a href="copyright.html">Copyright</a></li><li class="chapter-item expanded affix "><a href="dedication.html">Dedication</a></li><li class="chapter-item expanded affix "><a href="preface.html">Preface</a></li><li class="chapter-item expanded "><a href="api/index.html"><strong aria-hidden="true">1.</strong> API Reference</a><a class="toggle"><div>❱</div></a></li><li><ol class="section"><li class="chapter-item expanded "><a href="api/init.html"><strong aria-hidden="true">1.1.</strong> Initialization</a></li><li class="chapter-item expanded "><a href="api/msg.html"><strong aria-hidden="true">1.2.</strong> Messages</a></li><li class="chapter-item expanded "><a href="api/sock.html"><strong aria-hidden="true">1.3.</strong> Sockets</a></li><li class="chapter-item expanded "><a href="api/ctx.html"><strong aria-hidden="true">1.4.</strong> Contexts</a></li><li class="chapter-item expanded "><a href="api/pipe.html"><strong aria-hidden="true">1.5.</strong> Pipes</a></li><li class="chapter-item expanded "><a href="api/memory.html"><strong aria-hidden="true">1.6.</strong> Memory</a></li><li class="chapter-item expanded "><a href="api/time.html"><strong aria-hidden="true">1.7.</strong> Time</a></li><li class="chapter-item expanded "><a href="api/url.html"><strong aria-hidden="true">1.8.</strong> URLs</a></li><li class="chapter-item expanded "><a href="api/aio.html"><strong aria-hidden="true">1.9.</strong> Asynchronous I/O</a></li><li class="chapter-item expanded "><a href="api/synch.html"><strong aria-hidden="true">1.10.</strong> Synchronization</a></li><li class="chapter-item expanded "><a href="api/thread.html"><strong aria-hidden="true">1.11.</strong> Threads</a></li><li class="chapter-item expanded "><a href="api/logging.html"><strong aria-hidden="true">1.12.</strong> Logging</a></li><li class="chapter-item expanded "><a href="api/stats.html"><strong aria-hidden="true">1.13.</strong> Statistics</a></li><li class="chapter-item expanded "><a href="api/errors.html"><strong aria-hidden="true">1.14.</strong> Errors</a></li><li class="chapter-item expanded "><a href="api/stream.html"><strong aria-hidden="true">1.15.</strong> Streams</a></li><li class="chapter-item expanded "><a href="api/http.html"><strong aria-hidden="true">1.16.</strong> HTTP</a></li><li class="chapter-item expanded "><a href="api/misc.html"><strong aria-hidden="true">1.17.</strong> Miscellaneous</a></li><li class="chapter-item expanded "><a href="api/id_map.html"><strong aria-hidden="true">1.18.</strong> ID Map</a></li><li class="chapter-item expanded "><a href="api/args.html"><strong aria-hidden="true">1.19.</strong> Arguments Parser</a></li></ol></li><li class="chapter-item expanded "><a href="proto/index.html"><strong aria-hidden="true">2.</strong> Protocols</a><a class="toggle"><div>❱</div></a></li><li><ol class="section"><li class="chapter-item expanded "><a href="proto/bus.html"><strong aria-hidden="true">2.1.</strong> BUS Protocol</a></li><li class="chapter-item expanded "><a href="proto/pair.html"><strong aria-hidden="true">2.2.</strong> PAIR Protocol</a></li><li class="chapter-item expanded "><a href="proto/pub.html"><strong aria-hidden="true">2.3.</strong> PUB Protocol</a></li><li class="chapter-item expanded "><a href="proto/pull.html"><strong aria-hidden="true">2.4.</strong> PULL Protocol</a></li><li class="chapter-item expanded "><a href="proto/push.html"><strong aria-hidden="true">2.5.</strong> PUSH Protocol</a></li><li class="chapter-item expanded "><a href="proto/rep.html"><strong aria-hidden="true">2.6.</strong> REP Protocol</a></li><li class="chapter-item expanded "><a href="proto/req.html"><strong aria-hidden="true">2.7.</strong> REQ Protocol</a></li><li class="chapter-item expanded "><a href="proto/respondent.html"><strong aria-hidden="true">2.8.</strong> RESPONDENT Protocol</a></li><li class="chapter-item expanded "><a href="proto/sub.html"><strong aria-hidden="true">2.9.</strong> SUB Protocol</a></li><li class="chapter-item expanded "><a href="proto/surveyor.html"><strong aria-hidden="true">2.10.</strong> SURVEYOR Protocol</a></li></ol></li><li class="chapter-item expanded "><a href="tran/index.html"><strong aria-hidden="true">3.</strong> Transports</a><a class="toggle"><div>❱</div></a></li><li><ol class="section"><li class="chapter-item expanded "><a href="tran/inproc.html"><strong aria-hidden="true">3.1.</strong> Intra-Process Transport</a></li><li class="chapter-item expanded "><a href="tran/ipc.html"><strong aria-hidden="true">3.2.</strong> Inter-Process Transport</a></li><li class="chapter-item expanded "><a href="tran/socket.html"><strong aria-hidden="true">3.3.</strong> BSD Socket (Experimental)</a></li><li class="chapter-item expanded "><a href="tran/udp.html"><strong aria-hidden="true">3.4.</strong> UDP Transport (Experimental)</a></li></ol></li><li class="chapter-item expanded "><a href="migrate/index.html"><strong aria-hidden="true">4.</strong> Migration Guides</a><a class="toggle"><div>❱</div></a></li><li><ol class="section"><li class="chapter-item expanded "><a href="migrate/nng1.html"><strong aria-hidden="true">4.1.</strong> Migrating from NNG 1.x</a></li><li class="chapter-item expanded "><a href="migrate/nanomsg.html"><strong aria-hidden="true">4.2.</strong> Migrating from libnanomsg</a></li></ol></li><li class="chapter-item expanded "><a href="indexing.html">Index</a></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString();
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
