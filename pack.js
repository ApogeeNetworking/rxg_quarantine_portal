// Core Pack
import "packs/application"

// Bootstrap
require("@popperjs/core")
const bootstrap = require('bootstrap');
window.bootstrap = bootstrap

document.addEventListener("DOMContentLoaded", () => {
  new bootstrap.Tooltip(
    document.body, {
      selector: '[data-bs-toggle="tooltip"]',
      container: 'body',
      html: true
  })
})

// Load Roboto font and adjustment styles for Material UI.
import "@fontsource/roboto/300.css"
import "@fontsource/roboto/400.css"
import "@fontsource/roboto/500.css"
import "@fontsource/roboto/700.css"
import "stylesheets/material_adjustments"

// Load React-Rails helper context.
import 'react_components';
