// The pages' only script. Everything is a delegated listener on the document, so it keeps working whatever the
// pages render after it loaded.
(function () {
  "use strict";

  var storageKey = "secrethive-theme";

  // ── Light and dark ──────────────────────────────────────────────────────────────────────────
  // With nothing chosen the stylesheet follows the operating system. The button records an explicit choice;
  // choosing what the system already shows clears it again, so the page goes back to following the system.
  function systemPrefersDark() {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  }

  function currentTheme() {
    return document.documentElement.getAttribute("data-theme") || (systemPrefersDark() ? "dark" : "light");
  }

  function applyTheme(theme) {
    if (theme === "light" || theme === "dark") {
      document.documentElement.setAttribute("data-theme", theme);
    } else {
      document.documentElement.removeAttribute("data-theme");
    }

    document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
      button.textContent = currentTheme() === "dark" ? "☀" : "☾";
    });
  }

  function storedTheme() {
    try {
      return localStorage.getItem(storageKey);
    } catch (error) {
      return null;
    }
  }

  function chooseTheme(theme) {
    try {
      if (theme) {
        localStorage.setItem(storageKey, theme);
      } else {
        localStorage.removeItem(storageKey);
      }
    } catch (error) {
      // A browser that refuses storage keeps the choice for this page only.
    }

    applyTheme(theme);
  }

  document.addEventListener("click", function (event) {
    var toggle = event.target.closest ? event.target.closest("[data-theme-toggle]") : null;
    if (toggle) {
      chooseTheme(currentTheme() === "dark" ? "light" : "dark");
      return;
    }

    var choice = event.target.closest ? event.target.closest("[data-theme-choice]") : null;
    if (choice) {
      chooseTheme(choice.getAttribute("data-theme-choice") || null);
      return;
    }

    // A menu that is open closes on a click anywhere else, and after following one of its own links.
    document.querySelectorAll("details[data-menu][open]").forEach(function (menu) {
      // A button marked data-menu-stay works inside the menu (a folder of the vault list folds) and leaves it open.
      if (!menu.contains(event.target) || (event.target.closest && event.target.closest("a, button") && !event.target.closest("[data-menu-stay]"))) {
        menu.removeAttribute("open");
      }
    });
  });

  // And on Escape, from wherever the keyboard is.
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      document.querySelectorAll("details[data-menu][open]").forEach(function (menu) {
        menu.removeAttribute("open");
      });
    }
  });

  // The pages draw themselves after this script ran, and redraw on navigation: paint the button whenever one appears.
  new MutationObserver(function () {
    var button = document.querySelector("[data-theme-toggle]");
    if (button && !button.textContent.trim()) {
      applyTheme(storedTheme());
    }
  }).observe(document.documentElement, { childList: true, subtree: true });
  applyTheme(storedTheme());

  // ── The picker ──────────────────────────────────────────────────────────────────────────────
  // A picker shows the name of what was chosen until someone types. Selecting that name when the box is entered
  // or clicked makes the first key replace it, here in the browser, before the server has heard of anything:
  // otherwise what is typed lands behind the old name for as long as the answer takes to arrive.
  function selectPicked(event) {
    var box = event.target;
    if (box && box.matches && box.matches(".sh-picker input")) {
      box.select();
    }
  }

  document.addEventListener("focusin", selectPicked);
  document.addEventListener("click", selectPicked);

  // ── Clipboard ───────────────────────────────────────────────────────────────────────────────
  window.secretHive = {
    copy: async function (text) {
      // The clipboard API only exists on https and on localhost. Over plain http on a LAN address it is simply
      // absent, so fall back to the older way: a field off-screen, selected, copied, removed.
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }

      var field = document.createElement("textarea");
      field.value = text;
      field.setAttribute("readonly", "");
      field.style.position = "fixed";
      field.style.left = "-9999px";
      document.body.appendChild(field);
      field.select();
      try {
        return document.execCommand("copy");
      } finally {
        field.value = "";
        document.body.removeChild(field);
      }
    },
    theme: function () {
      return storedTheme() || "system";
    }
  };
  // ── The connection to the server ──────────────────────────────────────────────────────────
  // The two buttons of the bar shown when it dropped: try again now, or load the page anew when the server no
  // longer holds it.
  document.addEventListener("click", function (event) {
    var button = event.target.closest ? event.target.closest("[data-reconnect]") : null;
    if (!button) {
      return;
    }

    if (button.getAttribute("data-reconnect") === "retry" && window.Blazor && window.Blazor.reconnect) {
      window.Blazor.reconnect();
    } else {
      location.reload();
    }
  });

  // ── Tooltips ────────────────────────────────────────────────────────────────────────────────
  // Every title attribute becomes a tooltip drawn in the page's own style, instead of the browser's plain box (as in
  // FiGet). Nothing in the markup changes: while an element is pointed at or focused its title is moved aside, so the
  // browser does not show its own on top, and it is put back afterwards, unless the page gave it a new one meanwhile.
  // One element in <body>, placed from the target's rectangle, so a card that scrolls sideways cannot clip it.
  (function () {
    var tip = null;
    var target = null;
    var timer = 0;

    function element() {
      if (!tip) {
        tip = document.createElement("div");
        tip.className = "sh-tooltip";
        tip.setAttribute("role", "tooltip");
        tip.id = "sh-tooltip";
        tip.hidden = true;
        document.body.appendChild(tip);
      }

      return tip;
    }

    function place() {
      if (!target || !tip || tip.hidden) {
        return;
      }

      var rect = target.getBoundingClientRect();
      var box = tip.getBoundingClientRect();
      var gap = 8;
      var above = rect.top - box.height - gap >= 0;
      var top = above ? rect.top - box.height - gap : rect.bottom + gap;
      var left = rect.left + rect.width / 2 - box.width / 2;
      left = Math.max(6, Math.min(left, document.documentElement.clientWidth - box.width - 6));

      tip.classList.toggle("sh-tooltip-below", !above);
      tip.style.top = (top + window.scrollY) + "px";
      tip.style.left = (left + window.scrollX) + "px";
      tip.style.setProperty("--sh-tooltip-arrow", (rect.left + rect.width / 2 - left) + "px");
    }

    function show(el, text) {
      var node = element();
      node.textContent = text;
      node.hidden = false;
      el.setAttribute("aria-describedby", node.id);
      place();
      node.classList.add("sh-tooltip-on");
    }

    function hide() {
      window.clearTimeout(timer);
      if (target && target.hasAttribute("data-sh-title")) {
        if (!target.hasAttribute("title")) {
          target.setAttribute("title", target.getAttribute("data-sh-title"));
        }

        target.removeAttribute("data-sh-title");
        target.removeAttribute("aria-describedby");
      }

      target = null;
      if (tip) {
        tip.classList.remove("sh-tooltip-on");
        tip.hidden = true;
      }
    }

    function enter(el, delay) {
      if (el === target) {
        return;
      }

      hide();
      var text = el.getAttribute("title");
      if (!text) {
        return;
      }

      target = el;
      el.setAttribute("data-sh-title", text);
      el.removeAttribute("title");
      timer = window.setTimeout(function () {
        if (target === el) {
          show(el, text);
        }
      }, delay);
    }

    document.addEventListener("mouseover", function (event) {
      var el = event.target.closest ? event.target.closest("[title]") : null;
      if (el) {
        enter(el, 250);
      } else if (target && !target.contains(event.target)) {
        hide();
      }
    });

    document.addEventListener("focusin", function (event) {
      var el = event.target.closest ? event.target.closest("[title]") : null;
      if (el && el.matches(":focus-visible")) {
        enter(el, 0);
      }
    });

    // A tap gives no hover: tapping an (i) shows its text at once, tapping it again or anywhere else hides it.
    document.addEventListener("click", function (event) {
      var info = event.target.closest ? event.target.closest(".sh-info") : null;
      if (info) {
        if (info === target && tip && !tip.hidden) {
          hide();
        } else {
          var text = info.getAttribute("title") || info.getAttribute("data-sh-title");
          hide();
          if (text) {
            target = info;
            info.setAttribute("data-sh-title", text);
            info.removeAttribute("title");
            show(info, text);
          }
        }
      } else if (target) {
        hide();
      }
    });

    // Leaving the window from inside the element fires no mouseover anywhere else.
    document.addEventListener("mouseout", function (event) {
      if (!event.relatedTarget) {
        hide();
      }
    });
    document.addEventListener("focusout", hide);
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        hide();
      }
    });
    window.addEventListener("scroll", hide, true);
    window.addEventListener("resize", hide);
  })();

  // ── A secret beside its list ────────────────────────────────────────────────────────────────
  // While a secret's panel is open, the arrow keys show the one above or below it, and Escape closes it, unless the
  // keyboard is busy in a field, a dialog or a menu. Both follow the page's own links, so the server decides. It
  // listens before the other handlers, which would close an open menu first and leave nothing to tell it apart.
  document.addEventListener("keydown", function (event) {
    if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey || !document.querySelector(".sh-panel")) {
      return;
    }

    var busy = event.target.closest && event.target.closest("input, textarea, select, [contenteditable], .sh-dialog, details[data-menu][open]");
    if (busy || document.querySelector(".sh-dialog-backdrop, details[data-menu][open]")) {
      return;
    }

    if (event.key === "Escape") {
      var close = document.querySelector("[data-panel-close]");
      if (close) {
        close.click();
      }

      return;
    }

    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") {
      return;
    }

    var row = document.querySelector("tr.sh-selected");
    var next = row && (event.key === "ArrowDown" ? row.nextElementSibling : row.previousElementSibling);
    var link = next && next.querySelector("a[data-select]");
    if (link) {
      event.preventDefault();
      link.click();
      next.scrollIntoView({ block: "nearest" });
    }
  }, true);

  // ── Tables on a narrow screen ───────────────────────────────────────────────────────────────
  // The stylesheet turns a table into a list there, one line per cell. Each cell is told the name of its
  // column so that line can say what it is, and a cell with nothing in it is marked so it takes no line.
  function labelTable(table) {
    var heads = Array.prototype.map.call(table.querySelectorAll("thead th"), function (th) {
      return th.textContent.trim();
    });
    table.querySelectorAll("tbody tr").forEach(function (row) {
      var column = 0;
      Array.prototype.forEach.call(row.children, function (cell) {
        var span = cell.colSpan || 1;
        if (span === 1) {
          var label = heads[column] || "";
          if (cell.getAttribute("data-label") !== label) {
            cell.setAttribute("data-label", label);
          }
        }

        cell.classList.toggle("sh-cell-empty", span === 1 && cell.children.length === 0 && cell.textContent.trim() === "");
        column += span;
      });
    });
  }

  function labelTables() {
    document.querySelectorAll("table.sh-table").forEach(labelTable);
  }

  // The pages render rows after this script ran, and again whenever something changes.
  var labelling = false;
  new MutationObserver(function () {
    if (labelling) {
      return;
    }

    labelling = true;
    requestAnimationFrame(function () {
      labelling = false;
      labelTables();
    });
  }).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  labelTables();
})();
