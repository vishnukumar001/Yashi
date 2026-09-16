import fs from "fs/promises";
import path from "path";
import { GoogleGenAI, Type } from "@google/genai/node";
import { Memory, MemoryTransaction } from "./src/lib/memoryTypes";
import { dataFile, getSupabaseConfig, DATA_DIR } from "./server_paths";
import { createClient } from "@supabase/supabase-js";

const MEMORY_FILE = dataFile("memories.json");
const CONVERSATION_HISTORY_DIR = path.join(DATA_DIR, "conversation_history");
// Guard to prevent concurrent consolidation runs
let isConsolidating = false;

// Ensure conversation history directory exists
async function ensureConversationHistoryDir(): Promise<void> {
  try {
    await fs.mkdir(CONVERSATION_HISTORY_DIR, { recursive: true });
  } catch {
    // already exists
  }
}

/** Initialize Supabase client if configured */
function getSupabase() {
  const { url, key } = getSupabaseConfig();
  if (url && key) {
    return createClient(url, key);
  }
  return null;
}

// Safe file operations with fallback
export async function loadMemories(): Promise<Memory[]> {
  const supabase = getSupabase();
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from("memories")
        .select("*")
        .order("created_at", { ascending: true });
      
      if (error) throw error;
      if (data) {
        return data.map(m => ({
          id: m.id,
          category: m.category,
          text: m.text,
          createdAt: m.created_at,
          updatedAt: m.updated_at
        }));
      }
    } catch (error) {
      console.error("[Memory] Supabase load error, falling back to local:", error);
    }
  }

  try {
    const data = await fs.readFile(MEMORY_FILE, "utf-8");
    return JSON.parse(data) as Memory[];
  } catch (error: any) {
    // If file doesn't exist, return empty array
    if (error.code === "ENOENT") {
      return [];
    }
    console.error("[Memory] Error loading memories, returning fallback:", error);
    return [];
  }
}

export async function saveMemories(memories: Memory[]): Promise<void> {
  const supabase = getSupabase();
  if (supabase) {
    try {
      // Upsert all memories to Supabase
      const { error } = await supabase
        .from("memories")
        .upsert(memories.map(m => ({
          id: m.id,
          category: m.category,
          text: m.text,
          created_at: m.createdAt,
          updated_at: m.updatedAt
        })));
      
      if (error) throw error;
      console.log(`[Memory] Synced ${memories.length} memories to Supabase.`);
    } catch (error) {
      console.error("[Memory] Supabase sync error:", error);
    }
  }

  try {
    await fs.writeFile(MEMORY_FILE, JSON.stringify(memories, null, 2), "utf-8");
    console.log(`[Memory] Saved ${memories.length} memories to local file.`);
  } catch (error) {
    console.error("[Memory] Error writing local memory file:", error);
  }
}

export async function deleteMemoryFromStore(id: string): Promise<void> {
  const supabase = getSupabase();
  if (supabase) {
    try {
      const { error } = await supabase
        .from("memories")
        .delete()
        .eq("id", id);
      if (error) throw error;
    } catch (error) {
      console.error("[Memory] Supabase delete error:", error);
    }
  }

  let memories = await loadMemories();
  memories = memories.filter(m => m.id !== id);
  await saveMemories(memories);
}

// Format memory core to system instruction injections
export function formatSystemInstructionsWithMemories(
  baseInstruction: string,
  memories: Memory[],
  conversationSummary?: string
): string {
  if (memories.length === 0) {
    let block = baseInstruction + 
      "\n\n" +
      "=== YASHI MEMORY CORE ===\n" +
      "You do not possess any historic recollections of this companion yet. " +
      "As you speak, pay deep attention to who they are, their projects, relationships, and habits so you naturally grow closer over time.\n";
    if (conversationSummary) {
      block += `\nACTIVE CONVERSATION CONTEXT (RETAIN THIS TOPIC):\n${conversationSummary}\n`;
    }
    block += "=========================\n";
    return block;
  }

  // Group by category
  const grouped: Record<string, string[]> = {};
  memories.forEach((m) => {
    grouped[m.category] = grouped[m.category] || [];
    grouped[m.category].push(m.text);
  });

  let memoryBlock = 
    "\n\n" +
    "=== YASHI PERSISTENT MEMORY CORE (RECOLLECTIONS) ===\n" +
    "You have spoken with this user for a long duration. Below are your persistent recollections of who they are.\n" +
    "CRITICAL BRAND AND COGNITIVE PRINCIPLES:\n" +
    "- INTEGRATE MEMORIES INSTINCTIVELY: Always make conversational references feel completely smooth, natural, and human. NEVER say 'According to my memory files...', 'My recollection database indicates...', or 'As you told me on June 12th...'. Instead, speak of these details casually and supportively as a true friend would (e.g. 'Oh, since you're working on that website project...', 'I hope you're keeping up with your YouTube channel goals too!').\n" +
    "- COMPANIONSHIP DEPTH: Allow your witty and responsive personality to adapt with empathy, based on their goals, life events, emotional milestones, and preferences.\n\n";

  if (conversationSummary) {
    memoryBlock += `ACTIVE CONVERSATION CONTEXT (CURRENT ACTIVE TOPIC):\n${conversationSummary}\n\n`;
  }

  memoryBlock += "CURRENT PERSISTENT KNOWLEDGE CARD:\n";

  const categoriesOrdered = [
    { key: "identity", label: "Identity (Name, nick, profession, background)" },
    { key: "preference", label: "Preferences & Tastes (Likes, dislikes, games, movies)" },
    { key: "goal", label: "Active Goals & Aspirations" },
    { key: "project", label: "Ongoing Projects & Ecosystems" },
    { key: "relationship", label: "Key People & Relationships mentioned" },
    { key: "emotional", label: "Emotional Highlights & Core Milestones" },
    { key: "behavior", label: "Observed Traits & Behavioral Tendencies" },
  ];

  categoriesOrdered.forEach((cat) => {
    const list = grouped[cat.key] || [];
    if (list.length > 0) {
      memoryBlock += `* ${cat.label}:\n` + list.map(t => `  - ${t}`).join("\n") + "\n";
    }
  });

  memoryBlock += "====================================================\n";

  return baseInstruction + memoryBlock;
}

export async function summarizeConversation(history: { role: string; text: string }[]): Promise<string> {
  const dialogueContext = history.map(line => `${line.role === "user" ? "User" : "Yashi"}: ${line.text}`).join("\n");
  const prompt = `Summarize this ongoing conversation into a brief, 2-3 sentence context note. Focus on the current active task, the user's immediate goal, and the main topic being discussed. Keep it extremely concise so it can be used as context.\n\nConversation:\n${dialogueContext}\n\nSummary:`;
  try {
    const { text } = await unifiedGenerateText(prompt, true);
    return text.trim();
  } catch (e) {
    console.error("[Memory] Dialogue summarization error:", e);
    return "";
  }
}

import { unifiedGenerateText } from "./src/lib/providers/ai_factory";

export interface ConversationMessage {
  role: string;
  text: string;
  timestamp: string;
}

export async function saveConversationMessage(message: ConversationMessage): Promise<void> {
  const supabase = getSupabase();
  if (supabase) {
    try {
      const { error } = await supabase
        .from("conversations")
        .insert({
          role: message.role,
          text: message.text,
          created_at: message.timestamp
        });
      if (error) throw error;
    } catch (error) {
      console.error("[Memory] Supabase conversation save error:", error);
    }
  }
  
  // Also append to local file for redundancy
  try {
    const logPath = dataFile("conversation_history.jsonl");
    await fs.appendFile(logPath, JSON.stringify(message) + "\n", "utf-8");
  } catch (error) {
    console.error("[Memory] Local conversation save error:", error);
  }
  
  // Save to conversation history folder (per-session files)
  await saveConversationToFolder(message);
}

// Save each conversation message to a per-session file in conversation_history folder
async function saveConversationToFolder(message: ConversationMessage): Promise<void> {
  try {
    await ensureConversationHistoryDir();
    const dateStr = new Date(message.timestamp).toISOString().split('T')[0];
    const sessionFile = path.join(CONVERSATION_HISTORY_DIR, `session_${dateStr}.jsonl`);
    await fs.appendFile(sessionFile, JSON.stringify(message) + "\n", "utf-8");
  } catch (error) {
    console.error("[Memory] Conversation folder save error:", error);
  }
}

// Load conversation history from folder for a specific date
export async function loadConversationHistory(date?: string): Promise<ConversationMessage[]> {
  try {
    await ensureConversationHistoryDir();
    const targetDate = date || new Date().toISOString().split('T')[0];
    const sessionFile = path.join(CONVERSATION_HISTORY_DIR, `session_${targetDate}.jsonl`);
    
    const data = await fs.readFile(sessionFile, "utf-8");
    return data.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
  } catch (error: any) {
    if (error.code === "ENOENT") {
      return [];
    }
    console.error("[Memory] Load conversation history error:", error);
    return [];
  }
}

// List all available conversation history dates
export async function listConversationHistoryDates(): Promise<string[]> {
  try {
    await ensureConversationHistoryDir();
    const files = await fs.readdir(CONVERSATION_HISTORY_DIR);
    return files
      .filter(f => f.startsWith('session_') && f.endsWith('.jsonl'))
      .map(f => f.replace('session_', '').replace('.jsonl', ''))
      .sort()
      .reverse();
  } catch {
    return [];
  }
}

export async function processConversationSlice(
  apiKey: string,
  dialogueHistory: { role: string; text: string }[]
): Promise<Memory[] | null> {
  if (isConsolidating) {
    console.log("[Memory] Consolidation loop busy, skipping slice processing");
    return null;
  }

  if (dialogueHistory.length < 2) {
    return null;
  }

  isConsolidating = true;
  console.log("[Memory] Initiating pipeline for dialogue slice of length:", dialogueHistory.length);

  try {
    const currentMemories = await loadMemories();
    
    // Format memory map to help Gemini understand what to edit
    const memoryContext = currentMemories.map(m => `ID: ${m.id} | Category: ${m.category} | Fact: ${m.text}`).join("\n");
    const dialogueContext = dialogueHistory.map(line => `${line.role === "user" ? "User" : "Yashi"}: ${line.text}`).join("\n");

    const prompt = `You are Yashi's deep cognitive recollection engine. Your task is to analyze the recent conversation piece against previous persistent memories, and output precise update transactions.

### OBJECTIVE
Decide if any statements contain durable, important personal facts, enduring preferences, aspirations, ongoing projects, critical relationships, key historical emotional events, or behavioral trends.
Avoid cataloging small talk, greetings, general chit-chat, or fleeting sentences (e.g., ignore 'hello', 'how are you', 'waking up', 'lol').

### CURRENT USER MEMORIES:
${memoryContext || "(No memory records exist)"}

### RECENT DIALOGUE SLICE:
${dialogueContext}

### RULES
- ACTIONS:
  - "ADD": If new material information is introduced (e.g. user says 'My favorite food is lasagna' and it's not present).
  - "UPDATE": If previous information has evolved or is corrected (e.g. user says 'I changed my major to computer science' when memory says they study history). Provide the exact ID of the memory to replace.
  - "REMOVE": If a memory was explicitly disproven or the user directly asked Yashi to forget it.
- TEXT STYLE: Express the memories as clean, concise, third-person declarative summaries (e.g., 'The user is building a project named Yashi.', 'The user loves playing GTA 6.', 'The user enjoys technical and fast-paced styling explanations.'). Do not include conversational filler, quotes, or timestamps.
- ID: For ADD, leave blank. For UPDATE or REMOVE, provide the exact 'id' from the "Current user memories" list.

Return the result as a JSON object with a "transactions" array. Each transaction should have "action", "id", "category", and "text".`;

    const { text: resultText, provider } = await unifiedGenerateText(prompt, true);
    console.log(`[Memory] Consolidation using provider: ${provider}`);

    const cleanedText = resultText.replace(/```(?:json)?/gi, "").replace(/```/g, "").trim();
    const resultObj = JSON.parse(cleanedText);
    const transactions: MemoryTransaction[] = resultObj.transactions || [];

    if (transactions.length === 0) {
      console.log("[Memory] Zero transactions generated. Ignored routine conversations.");
      isConsolidating = false;
      return null;
    }

    console.log(`[Memory] Processing ${transactions.length} memory updates:`, JSON.stringify(transactions));

    let updatedMemories = [...currentMemories];
    const timestamp = new Date().toISOString();

    for (const trx of transactions) {
      if (trx.action === "ADD") {
        const newMemory: Memory = {
          id: Math.random().toString(36).substring(2, 11),
          category: trx.category,
          text: trx.text,
          createdAt: timestamp,
          updatedAt: timestamp
        };
        updatedMemories.push(newMemory);
      } else if (trx.action === "UPDATE") {
        const tarIndex = updatedMemories.findIndex(m => m.id === trx.id);
        if (tarIndex !== -1) {
          updatedMemories[tarIndex] = {
            ...updatedMemories[tarIndex],
            category: trx.category,
            text: trx.text,
            updatedAt: timestamp
          };
        } else {
          // Fallback, treat as ADD if ID not matched
          const newMemory: Memory = {
            id: Math.random().toString(36).substring(2, 11),
            category: trx.category,
            text: trx.text,
            createdAt: timestamp,
            updatedAt: timestamp
          };
          updatedMemories.push(newMemory);
        }
      } else if (trx.action === "REMOVE") {
        updatedMemories = updatedMemories.filter(m => m.id !== trx.id);
      }
    }

    await saveMemories(updatedMemories);
    isConsolidating = false;
    return updatedMemories;

  } catch (error) {
    console.error("[Memory] Consolidation failure:", error);
    isConsolidating = false;
    return null;
  }
}

// ============================================================
// SESSION MANAGEMENT — Persist dialogue history per session
// ============================================================

export const SESSION_DIR = path.join(DATA_DIR, "sessions");
let currentSessionId: string | null = null;

async function ensureSessionDir(): Promise<void> {
  try {
    await fs.mkdir(SESSION_DIR, { recursive: true });
  } catch {}
}

export function setCurrentSessionId(sessionId: string): void {
  currentSessionId = sessionId;
}

export function getCurrentSessionId(): string | null {
  return currentSessionId;
}

export async function saveSessionDialogue(sessionId: string, dialogueHistory: { role: string; text: string }[]): Promise<void> {
  try {
    await ensureSessionDir();
    const sessionFile = path.join(SESSION_DIR, `${sessionId}.json`);
    const data = {
      sessionId,
      updatedAt: new Date().toISOString(),
      dialogueHistory: dialogueHistory.slice(-50), // Keep last 50 exchanges
    };
    await fs.writeFile(sessionFile, JSON.stringify(data, null, 2), "utf-8");
  } catch (error) {
    console.error("[Session] Save error:", error);
  }
}

export async function loadSessionDialogue(sessionId: string): Promise<{ role: string; text: string }[]> {
  try {
    await ensureSessionDir();
    const sessionFile = path.join(SESSION_DIR, `${sessionId}.json`);
    const data = await fs.readFile(sessionFile, "utf-8");
    const parsed = JSON.parse(data);
    return parsed.dialogueHistory || [];
  } catch (error: any) {
    if (error.code === "ENOENT") return [];
    console.error("[Session] Load error:", error);
    return [];
  }
}

export async function loadLatestSessionDialogue(): Promise<{ role: string; text: string }[]> {
  try {
    await ensureSessionDir();
    const files = await fs.readdir(SESSION_DIR);
    const sessionFiles = files.filter(f => f.endsWith('.json')).sort().reverse();
    if (sessionFiles.length === 0) return [];
    const latestFile = path.join(SESSION_DIR, sessionFiles[0]);
    const data = await fs.readFile(latestFile, "utf-8");
    const parsed = JSON.parse(data);
    return parsed.dialogueHistory || [];
  } catch {
    return [];
  }
}

export async function listSessions(): Promise<string[]> {
  try {
    await ensureSessionDir();
    const files = await fs.readdir(SESSION_DIR);
    return files.filter(f => f.endsWith('.json')).map(f => f.replace('.json', '')).sort().reverse();
  } catch {
    return [];
  }
}
