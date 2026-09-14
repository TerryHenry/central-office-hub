import qrcode from './assets/qrcode/qrcode.mjs';

// Bridges the ES module build into a plain global for app.js (a classic, non-module
// script) to call -- only ever invoked from inside a later event handler, well after both
// scripts have finished loading, so the module/classic-script load-order split is fine.
window.renderTotpQr = function renderTotpQr(container, text) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  container.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2 });
};
