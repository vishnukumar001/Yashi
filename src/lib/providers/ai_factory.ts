import { GoogleGenAI } from "@google/genai/node";
import { Groq } from "groq-sdk";
import { getGeminiApiKey, getGroqApiKey, getOpenRouterApiKey, getNvidiaApiKey } from "../../../server_paths";
import { DEFAULT_MODELS, PROVIDER_PRIORITY, ProviderType } from "./providerTypes";

// Determine provider order from AI_PROVIDER env var, or use default priority
function getProviderOrder(): ProviderType[] {
  const envProvider = process.env.AI_PROVIDER?.toLowerCase();
  if (envProvider && PROVIDER_PRIORITY.includes(envProvider as ProviderType)) {
    // Put the selected provider first, then the rest in default order
    const rest = PROVIDER_PRIORITY.filter(p => p !== envProvider);
    return [envProvider as ProviderType, ...rest];
  }
  return PROVIDER_PRIORITY;
}

export interface AIProvider {
  name: string;
  generateText(prompt: string, schema?: any): Promise<string>;
}

class GeminiProvider implements AIProvider {
  name = "Gemini";
  async generateText(prompt: string, schema?: any): Promise<string> {
    const apiKey = getGeminiApiKey();
    if (!apiKey) throw new Error("Gemini API key not configured");
    const genAI = new GoogleGenAI({ apiKey });
    const response: any = await genAI.models.generateContent({
      model: DEFAULT_MODELS.gemini,
      contents: prompt,
    });
    // Prefer the standardized `text` field when present, otherwise try fallbacks
    return (response?.text ?? (response?.output?.[0]?.content?.[0]?.text) ?? "").toString();
  }
}

class GroqProvider implements AIProvider {
  name = "Groq";
  async generateText(prompt: string, schema?: any): Promise<string> {
    const apiKey = getGroqApiKey();
    if (!apiKey) throw new Error("Groq API key not configured");
    const groq = new Groq({ apiKey });
    const completion = await groq.chat.completions.create({
      messages: [{ role: "user", content: prompt }],
      model: DEFAULT_MODELS.groq,
      response_format: schema ? { type: "json_object" } : undefined,
    });
    return completion.choices[0]?.message?.content || "";
  }
}

class OpenRouterProvider implements AIProvider {
  name = "OpenRouter";
  async generateText(prompt: string, schema?: any): Promise<string> {
    const apiKey = getOpenRouterApiKey();
    if (!apiKey) throw new Error("OpenRouter API key not configured");
    const { default: OpenAI } = await import("openai");
    const openai = new OpenAI({
      baseURL: "https://openrouter.ai/api/v1",
      apiKey,
    });
    const completion = await openai.chat.completions.create({
      model: DEFAULT_MODELS.openrouter,
      messages: [{ role: "user", content: prompt }],
      response_format: schema ? { type: "json_object" } : undefined,
    });
    return completion.choices[0]?.message?.content || "";
  }
}

class NvidiaProvider implements AIProvider {
  name = "NVIDIA Nemotron";
  async generateText(prompt: string, schema?: any): Promise<string> {
    const apiKey = getNvidiaApiKey();
    if (!apiKey) throw new Error("NVIDIA API key not configured");
    const { default: OpenAI } = await import("openai");
    const openai = new OpenAI({
      baseURL: "https://integrate.api.nvidia.com/v1",
      apiKey,
    });
    const completion = await openai.chat.completions.create({
      model: DEFAULT_MODELS.nvidia,
      messages: [{ role: "user", content: prompt }],
      response_format: schema ? { type: "json_object" } : undefined,
      temperature: 0.3,
      max_tokens: 4096,
    });
    return completion.choices[0]?.message?.content || "";
  }
}

export async function unifiedGenerateText(prompt: string, schema?: any): Promise<{ text: string; provider: string }> {
  const providerOrder = getProviderOrder();
  const providerMap: Record<string, AIProvider> = {
    gemini: new GeminiProvider(),
    nvidia: new NvidiaProvider(),
    groq: new GroqProvider(),
    openrouter: new OpenRouterProvider(),
  };

  const providers = providerOrder.map(p => providerMap[p]).filter(Boolean);

  let lastError: Error | null = null;
  for (const provider of providers) {
    try {
      console.log(`[AI Factory] Attempting ${provider.name}...`);
      const text = await provider.generateText(prompt, schema);
      return { text, provider: provider.name };
    } catch (error: any) {
      console.warn(`[AI Factory] ${provider.name} failed: ${error.message}`);
      lastError = error;
    }
  }
  throw new Error(`All AI providers failed. Last error: ${lastError?.message}`);
}