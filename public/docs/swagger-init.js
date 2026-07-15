// Inizializzazione Swagger UI per GET /docs. File esterno, non inline:
// la CSP impostata all'edge (script-src senza 'unsafe-inline') copre anche
// le pagine servite dal Worker.
window.onload = function () {
  window.ui = SwaggerUIBundle({
    url: "/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    plugins: [SwaggerUIBundle.plugins.DownloadUrl],
    layout: "StandaloneLayout",
  });
};
