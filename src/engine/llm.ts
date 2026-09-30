import Anthropic from "@anthropic-ai/sdk";
import type { Suggestion, UnrecognizedLine, ValueMode, VendorId } from "./types";
import { SBM_PARAMS, SBM_INDEX } from "./sbm";
import { proposeExtraction } from "./classifier";
import { captureGroupCount, modeFitsType } from "./mappings";

/**
 * Optional LLM assist for the Training Studio. The administrator supplies
 * their own Anthropic API key (kept in this browser only). The offline
 * classifier keeps working without it.
 *
 * Every proposal the model returns is re-checked locally before it reaches the
 * UI: the regex must compile AND match the line it was invented for, the value
 * mode must fit the SBM parameter type, and capture/list modes must really
 * declare the capture group. Anything that fails falls back to the offline
 * classifier's own extraction, so a chatty model cannot store garbage.
 */
export interface LlmSettings {
  apiKey: string;
  model: string;
}

export const DEFAULT_LLM_MODEL = "claude-opus-5";

/** Lines per request. Larger batches blow the output-token budget. */
const BATCH_SIZE = 40;

const SYSTEM = `You are the mapping assistant inside NetSentinel AI, a vendor-agnostic network configuration compliance auditor.
You receive raw CLI lines from a network device configuration that the built-in parsers did not understand.
Map each line to the most appropriate parameter of the Security Baseline Model (SBM) listed below, or "none" when the line carries no security meaning.

Return ONLY a JSON array (no prose, no code fences). One object per input line:
{"line": <line number>, "param": "<sbm key or none>", "confidence": <0..1>, "valueMode": "const|capture|polarity|list|count|flag", "value": <value when valueMode is const; the extracted value otherwise>, "pattern": "<JavaScript regex matching this command family, with a capture group for the value when relevant>", "reason": "<one short sentence>"}

Rules for "pattern": it must be a case-insensitive JavaScript regular expression, anchored with ^, that MATCHES THE LINE YOU WERE GIVEN. Keep the command verb and vocabulary words literal; replace instance data (addresses, interface and object names, quoted strings, integers) with classes such as \\S+, \\d+, "[^"]*" or \\d{1,3}(?:\\.\\d{1,3}){3} so sibling commands match the same rule. Capture group 1 must hold the value for "capture" and "list".

Rules for "valueMode" by parameter type: boolean -> polarity (an enable/disable word decides), flag (presence means true) or const; number -> capture with a group that parses as a number, or count for genuine counters; string -> capture; list -> list with a capture group. Never use flag/polarity/count on a list or string parameter.

Example: line "configure sntp-client primary 10.10.50.10 vr VR-Default" ->
{"line": 76, "param": "time.ntp_servers", "confidence": 0.9, "valueMode": "list", "value": "10.10.50.10", "pattern": "^configure\\\\s+sntp-client\\\\s+(?:primary|secondary)\\\\s+(\\\\d{1,3}(?:\\\\.\\\\d{1,3}){3})", "reason": "SNTP time source"}

SBM parameters:
${SBM_PARAMS.map((p) => `- ${p.key} (${p.type}): ${p.label} — ${p.description}`).join("\n")}`;

export interface LlmResult {
  suggestions: Record<number, Suggestion>;
  model: string;
  inputTokens: number;
  outputTokens: number;
  /** lines that came back with a usable proposal */
  covered: number;
  /** lines the model returned nothing usable for */
  skipped: number;
}

const MODES: ValueMode[] = ["const", "capture", "polarity", "list", "count", "flag"];

export async function suggestWithLlm(lines: UnrecognizedLine[], vendor: VendorId, vendorHint: string, settings: LlmSettings): Promise<LlmResult> {
  const client = new Anthropic({ apiKey: settings.apiKey, dangerouslyAllowBrowser: true });
  const model = settings.model || DEFAULT_LLM_MODEL;
  const suggestions: Record<number, Suggestion> = {};
  let inputTokens = 0;
  let outputTokens = 0;
  let lastModel = model;

  for (let start = 0; start < lines.length; start += BATCH_SIZE) {
    const batch = lines.slice(start, start + BATCH_SIZE);
    const user = `Vendor/OS hint: ${vendorHint || vendor}\n\nLines:\n${batch.map((l) => `${l.line}: ${l.text}`).join("\n")}`;
    let response: Anthropic.Message;
    try {
      response = await client.messages.create({
        model,
        max_tokens: 8000,
        system: SYSTEM,
        messages: [{ role: "user", content: user }],
      });
    } catch (error) {
      if (error instanceof Anthropic.AuthenticationError) throw new Error("The API key was rejected. Check the key in Settings.");
      if (error instanceof Anthropic.RateLimitError) throw new Error("Rate limited by the API. Try again in a moment.");
      if (error instanceof Anthropic.APIConnectionError) throw new Error("Could not reach api.anthropic.com. Hosted viewers may block outbound requests; run the app locally or from GitHub Pages to use LLM assist.");
      if (error instanceof Anthropic.APIError) throw new Error(`API error ${error.status}: ${error.message}`);
      throw error;
    }
    if (response.stop_reason === "refusal") throw new Error("The model declined this request.");
    lastModel = response.model;
    inputTokens += response.usage.input_tokens;
    outputTokens += response.usage.output_tokens;
    const text = response.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map((b) => b.text)
      .join("\n");
    if (response.stop_reason === "max_tokens" && !text.trimEnd().endsWith("]")) {
      throw new Error(`The model's answer was cut off after ${response.usage.output_tokens} tokens. Filter the queue to fewer lines and try again.`);
    }
    for (const item of extractJsonArray(text)) mergeItem(item, batch, suggestions);
  }

  const covered = Object.keys(suggestions).length;
  return { suggestions, model: lastModel, inputTokens, outputTokens, covered, skipped: lines.length - covered };
}

function mergeItem(item: Record<string, unknown>, batch: UnrecognizedLine[], out: Record<number, Suggestion>): void {
  const line = Number(item.line);
  const param = String(item.param ?? "none");
  if (!Number.isFinite(line) || param === "none" || !SBM_INDEX[param]) return;
  const src = batch.find((l) => l.line === line);
  if (!src) return;

  const fallback = proposeExtraction(src.text, param);
  const type = SBM_INDEX[param].type;

  // 1. The pattern must compile AND actually match the line it was invented for.
  let pattern = typeof item.pattern === "string" && item.pattern.trim() ? item.pattern.trim() : fallback.pattern;
  try {
    if (!new RegExp(pattern, "i").test(src.text)) pattern = fallback.pattern;
  } catch {
    pattern = fallback.pattern;
  }

  // 2. The value mode must fit the parameter type.
  let valueMode = MODES.includes(item.valueMode as ValueMode) ? (item.valueMode as ValueMode) : fallback.valueMode;
  if (!modeFitsType(param, valueMode)) valueMode = fallback.valueMode;

  // 3. capture/list need a real capture group; otherwise fall back to the offline proposal.
  if ((valueMode === "capture" || valueMode === "list") && captureGroupCount(pattern, "i") < 1) {
    pattern = fallback.pattern;
    valueMode = modeFitsType(param, fallback.valueMode) ? fallback.valueMode : valueMode;
  }
  if ((valueMode === "capture" || valueMode === "list") && captureGroupCount(pattern, "i") < 1) return;

  // 4. A number parameter must end up with something that parses as a number.
  if (type === "number" && valueMode === "capture") {
    const g = src.text.match(new RegExp(pattern, "i"))?.[1];
    if (!g || !/^v?\d+(?:\.\d+)?$/i.test(g.trim())) {
      pattern = fallback.pattern;
      valueMode = fallback.valueMode;
    }
  }
  // 5. Whatever survived must still be storable in this parameter.
  if (!modeFitsType(param, valueMode)) return;

  const usedFallback = pattern === fallback.pattern && valueMode === fallback.valueMode;
  const confidence = Number.isFinite(Number(item.confidence)) ? Math.max(0, Math.min(0.99, Number(item.confidence))) : 0.5;
  out[line] = {
    param,
    confidence,
    valueMode,
    constValue: valueMode === "const" ? ((item.value as Suggestion["constValue"]) ?? fallback.constValue ?? true) : fallback.constValue,
    captureGroup: valueMode === "capture" || valueMode === "list" ? 1 : fallback.captureGroup,
    transform: fallback.transform,
    pattern,
    reasons: [typeof item.reason === "string" ? item.reason : "LLM suggestion"],
    extractedValue: (item.value as Suggestion["extractedValue"]) ?? fallback.extractedValue,
    extractionValid: usedFallback ? fallback.extractionValid : true,
    source: "llm",
  };
}

function extractJsonArray(text: string): Array<Record<string, unknown>> {
  const cleaned = text.replace(/```(?:json)?/g, "").trim();
  const start = cleaned.indexOf("[");
  const end = cleaned.lastIndexOf("]");
  if (start < 0 || end < 0) return [];
  try {
    const parsed = JSON.parse(cleaned.slice(start, end + 1));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}
