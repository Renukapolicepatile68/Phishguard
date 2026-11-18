if ("serviceWorker" in navigator &&
    (window.isSecureContext || window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1")) {
  navigator.serviceWorker.register("./sw.js").catch(error => {
    console.error("PhishGuard service worker registration failed.", error);
  });
}

const installButton = document.getElementById("installBtn");
let installPrompt;

if (installButton) {
  window.addEventListener("beforeinstallprompt", event => {
    event.preventDefault();
    installPrompt = event;
    installButton.classList.remove("hidden");
  });

  installButton.addEventListener("click", async () => {
    if (!installPrompt) return;
    try {
      installPrompt.prompt();
      await installPrompt.userChoice;
      installPrompt = null;
      installButton.classList.add("hidden");
    } catch (error) {
      console.error("PhishGuard installation prompt failed.", error);
    }
  });

  window.addEventListener("appinstalled", () => {
    installPrompt = null;
    installButton.classList.add("hidden");
  });
}
