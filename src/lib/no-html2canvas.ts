/**
 * jsPDF lazily imports html2canvas and DOMPurify for its `doc.html()` helper.
 * NetSentinel builds every PDF from text and tables, never from DOM capture,
 * and those two libraries embed image data URIs that stop a published page
 * from being shared. They are aliased to this stub in vite.config.ts.
 */
function unavailable(): never {
  throw new Error("doc.html() is not available in this build: NetSentinel renders PDFs from text, not from DOM capture.");
}
export default unavailable;
export const sanitize = unavailable;
