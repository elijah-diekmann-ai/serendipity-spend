(() => {
  document.documentElement.classList.add("js");

  const drawer = document.getElementById("expense-drawer");
  const drawerContent = document.getElementById("drawer-content");

  function openDrawer() {
    if (!drawer) return;
    drawer.classList.add("drawer--open");
    document.body.classList.add("drawer-open");
    drawer.setAttribute("aria-hidden", "false");
  }

  function closeDrawer() {
    if (!drawer) return;
    drawer.classList.remove("drawer--open");
    document.body.classList.remove("drawer-open");
    drawer.setAttribute("aria-hidden", "true");
  }

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;

    if (target.closest("[data-drawer-open]")) {
      openDrawer();
      return;
    }

    const close = target.closest("[data-drawer-close]");
    if (close) {
      event.preventDefault();
      closeDrawer();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeDrawer();
  });

  document.body.addEventListener("htmx:afterSwap", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    if (target.id !== "drawer-content") return;
    if (drawerContent && drawerContent.textContent && drawerContent.textContent.trim()) {
      openDrawer();
    }
  });

  document.body.addEventListener("htmx:afterRequest", (event) => {
    const elt = event.target;
    if (!(elt instanceof HTMLElement)) return;

    if (elt.id === "upload-form" && event.detail?.successful) {
      const clearBtn = document.getElementById("clear-files");
      if (clearBtn instanceof HTMLButtonElement) clearBtn.click();
    }
  });
})();

