// The light or dark choice, applied before the first paint. Only an explicit choice is stored; with none, the
// stylesheet follows the operating system on its own.
(function () {
    try {
        var chosen = localStorage.getItem("secrethive-theme");
        if (chosen === "light" || chosen === "dark") {
            document.documentElement.setAttribute("data-theme", chosen);
        }
    } catch (error) {
    }
})();
