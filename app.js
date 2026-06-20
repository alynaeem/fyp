const MODULE_BASE = "/js/modules/";
const MODULE_MANIFEST_URL = `${MODULE_BASE}manifest.json?v=1`;

function loadClassicScript(src) {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.async = false;
    script.onload = resolve;
    script.onerror = () => reject(new Error(`Failed to load ${src}`));
    document.head.appendChild(script);
  });
}

async function bootDarkPulseModules() {
  const response = await fetch(MODULE_MANIFEST_URL, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Could not load module manifest: HTTP ${response.status}`);
  }

  const modules = await response.json();
  for (const moduleName of modules) {
    await loadClassicScript(`${MODULE_BASE}${moduleName}?v=1`);
  }
}

bootDarkPulseModules().catch(error => {
  console.error(error);
  const target = document.getElementById("loginInfo") || document.body;
  const message = document.createElement("div");
  message.className = "test-result";
  message.textContent = `DarkPulse failed to load JavaScript modules: ${error.message}`;
  target.appendChild(message);
});
