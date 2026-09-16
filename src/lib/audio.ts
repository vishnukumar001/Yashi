/**
 * Audio handling utility for Yashi Live API Voice stream.
 * Handles:
 * - 16kHz layout sampling for microphone stream (via AudioWorklet).
 * - Raw Little Endian Int16 PCM translation.
 * - 24kHz layout output sampling for model voice playback.
 * - Gapless double-buffer queue scheduler.
 * - Interrupt signal immediate stop.
 * - Input & Output AnalyserNodes for real-time waveform visuals.
 */

export type LiveState = "disconnected" | "connecting" | "listening" | "speaking";

// Float conversion helper: converts signed Int16 array buffer to Float32Array [-1.0, 1.0]
function pcm16ToFloats(uint8Array: Uint8Array): Float32Array {
  const int16 = new Int16Array(
    uint8Array.buffer,
    uint8Array.byteOffset,
    uint8Array.byteLength / 2
  );
  const floats = new Float32Array(int16.length);
  for (let i = 0; i < int16.length; i++) {
    floats[i] = int16[i] / 32768.0;
  }
  return floats;
}

// Convert Base64 string to Uint8Array
function base64ToUint8Array(base64: string): Uint8Array {
  const binaryString = window.atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// Convert ArrayBuffer (Int16) to Base64 String
function int16ArrayBufferToBase64(arrayBuffer: ArrayBuffer): string {
  const bytes = new Uint8Array(arrayBuffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Inline AudioWorklet processor code — avoids path resolution and network/CORS issues
// Inline AudioWorklet processor code — avoids path resolution and network/CORS issues
// in Electron, packaged apps, and desktop webviews.
// Features real-time downsampling to 16kHz Int16 PCM and active output keeping Chrome graph alive.
const MIC_WORKLET_CODE = `
class YashiMicProcessor extends AudioWorkletProcessor {
  constructor(options) {
    super(options);
    this._sourceRate = (typeof sampleRate !== 'undefined' ? sampleRate : 16000);
    this._bufferSize = 2048;
    this._buffer = new Float32Array(this._bufferSize);
    this._bufferIndex = 0;
    this._port = this.port;
    this._port.onmessage = (event) => {
      if (event.data === 'stop') {
        this._flushBuffer();
      }
    };
  }
  process(inputs, outputs) {
    const input = inputs[0];
    const output = outputs[0];
    if (input && input.length > 0) {
      const channelData = input[0];
      // Keep Chrome audio graph rendering thread active by piping channelData to outputs
      if (output && output.length > 0) {
        output[0].set(channelData);
      }
      for (let i = 0; i < channelData.length; i++) {
        this._buffer[this._bufferIndex++] = channelData[i];
        if (this._bufferIndex >= this._bufferSize) {
          this._flushBuffer();
        }
      }
    }
    return true;
  }
  _flushBuffer() {
    if (this._bufferIndex > 0) {
      const inputSlice = this._buffer.subarray(0, this._bufferIndex);
      let resampled;
      if (!this._sourceRate || this._sourceRate === 16000 || Math.abs(this._sourceRate - 16000) < 50) {
        resampled = inputSlice;
      } else {
        // High-precision linear resampler to 16kHz
        const ratio = this._sourceRate / 16000;
        const newLen = Math.round(inputSlice.length / ratio);
        resampled = new Float32Array(newLen);
        for (let i = 0; i < newLen; i++) {
          const srcIdx = i * ratio;
          const i0 = Math.floor(srcIdx);
          const i1 = Math.min(i0 + 1, inputSlice.length - 1);
          const frac = srcIdx - i0;
          resampled[i] = inputSlice[i0] * (1 - frac) + inputSlice[i1] * frac;
        }
      }
      const pcmData = new Int16Array(resampled.length);
      for (let i = 0; i < resampled.length; i++) {
        const s = Math.max(-1, Math.min(1, resampled[i]));
        pcmData[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
      }
      this._port.postMessage(pcmData.buffer, [pcmData.buffer]);
      this._bufferIndex = 0;
    }
  }
}
try { registerProcessor('yashi-mic-processor', YashiMicProcessor); } catch (e) {}
`;

export class YashiAudioSession {
  private ws: WebSocket | null = null;
  
  // Audios contexts (separate to match exact required sample rates)
  private inputAudioCtx: AudioContext | null = null;
  private outputAudioCtx: AudioContext | null = null;
  
  // Audio sources & processors
  private micStream: MediaStream | null = null;
  private micSourceNode: MediaStreamAudioSourceNode | null = null;
  private micWorkletNode: AudioWorkletNode | null = null;
  private micScriptNode: ScriptProcessorNode | null = null;
  
  // Visualisers
  public inputAnalyser: AnalyserNode | null = null;
  public outputAnalyser: AnalyserNode | null = null;
  private outputGainNode: GainNode | null = null;
  
  // Buffering / Playback details
  private nextStartTime = 0;
  private activeSources: AudioBufferSourceNode[] = [];
  
  // State Callbacks
  private onStateChange: (state: LiveState) => void;
  private onTranscription: (role: "user" | "model", text: string) => void;
  private onToolCall: (name: string, args: any, callback: (result: any) => void) => void;
  private onError: (error: string) => void;
  private onMemorySync?: (memories: any[]) => void;
  private onConfirmationRequest?: (id: string, message: string) => void;
  
  private currentState: LiveState = "disconnected";
  private isActivated = false;
  
  // Reconnection logic
  private reconnecting = false;
  private reconnectAttempts = 0;
  private readonly MAX_RECONNECT_ATTEMPTS = 10;
  private readonly BASE_RECONNECT_DELAY_MS = 1000;
  private userInitiatedDisconnect = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private keepAliveTimer: ReturnType<typeof setInterval> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;

  constructor(handlers: {
    onStateChange: (state: LiveState) => void;
    onTranscription: (role: "user" | "model", text: string) => void;
    onToolCall: (name: string, args: any, callback: (result: any) => void) => void;
    onError: (error: string) => void;
    onMemorySync?: (memories: any[]) => void;
    onConfirmationRequest?: (id: string, message: string) => void;
  }) {
    this.onStateChange = handlers.onStateChange;
    this.onTranscription = handlers.onTranscription;
    this.onToolCall = handlers.onToolCall;
    this.onError = handlers.onError;
    this.onMemorySync = handlers.onMemorySync;
    this.onConfirmationRequest = handlers.onConfirmationRequest;
  }

  private setState(state: LiveState) {
    this.currentState = state;
    this.onStateChange(state);
  }

  public getState(): LiveState {
    return this.currentState;
  }

  /**
   * Approve or deny a pending sensitive action shown in the UI banner.
   */
  public respondToConfirmation(id: string, approved: boolean) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: "confirmationResponse",
        id,
        approved,
      }));
    }
  }

  /**
   * Pushes a compressed JPEG base64 screenshot frame directly to the live WebSocket server.
   */
  public sendVideoFrame(base64Data: string) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN && this.currentState !== "disconnected") {
      try {
        this.ws.send(JSON.stringify({ type: "video", video: base64Data }));
      } catch (err) {
        console.error("[Yashi] Failed to send video frame:", err);
      }
    }
  }

  // Requests microphone and creates connections
  public async connect() {
    if (this.isActivated) return;
    this.isActivated = true;
    this.userInitiatedDisconnect = false;
    this.reconnectAttempts = 0;
    this.setState("connecting");

    // Initialize and resume AudioContexts SYNCHRONOUSLY during the user's click gesture
    const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioContextClass) {
      this.onError("Holographic audio link unsupported: Web Audio API missing in browser.");
      this.disconnect();
      return;
    }

    try {
      if (!this.inputAudioCtx || this.inputAudioCtx.state === "closed") {
        try {
          this.inputAudioCtx = new AudioContextClass({ sampleRate: 16000 });
        } catch {
          this.inputAudioCtx = new AudioContextClass();
        }
      }
      if (!this.outputAudioCtx || this.outputAudioCtx.state === "closed") {
        try {
          this.outputAudioCtx = new AudioContextClass({ sampleRate: 24000 });
        } catch {
          this.outputAudioCtx = new AudioContextClass();
        }
      }

      // Resume immediately while user gesture activation is valid
      if (this.inputAudioCtx.state === "suspended") {
        this.inputAudioCtx.resume().catch(() => {});
      }
      if (this.outputAudioCtx.state === "suspended") {
        this.outputAudioCtx.resume().catch(() => {});
      }
    } catch (ctxErr) {
      console.warn("Synchronous AudioContext prep error:", ctxErr);
    }

    try {
      // 1. Establish custom WebSocket server bridge
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      this.ws = new WebSocket(`${protocol}//${window.location.host}/live`);
      this.ws.binaryType = "blob";

      this.ws.onopen = async () => {
        console.log("[Yashi] Connected to server side WS bridge");
        this.reconnectAttempts = 0;
        this.reconnecting = false;
        try {
          // Guard against early user disconnect during connection setup
          if (!this.isActivated) return;

          if (!this.inputAudioCtx || !this.outputAudioCtx) {
            throw new Error("AudioContext initialization failed.");
          }

          // Ensure Audio Contexts are active and resumed
          if (this.inputAudioCtx.state === "suspended") {
            await this.inputAudioCtx.resume().catch(() => {});
          }
          if (this.outputAudioCtx.state === "suspended") {
            await this.outputAudioCtx.resume().catch(() => {});
          }

          // Auto-resume contexts if browser/macOS suspends them during silence or inactivity
          const attachAutoResume = (ctx: AudioContext, name: string) => {
            ctx.onstatechange = () => {
              if (ctx.state === "suspended" && this.isActivated && !this.userInitiatedDisconnect) {
                console.log(`[Yashi Audio] ${name} suspended by browser, auto-resuming...`);
                ctx.resume().catch(() => {});
              }
            };
          };
          attachAutoResume(this.inputAudioCtx, "inputAudioCtx");
          attachAutoResume(this.outputAudioCtx, "outputAudioCtx");
          
          // Setup custom output Analyser & Volume Gains
          this.outputGainNode = this.outputAudioCtx.createGain();
          this.outputAnalyser = this.outputAudioCtx.createAnalyser();
          this.outputAnalyser.fftSize = 256;
          this.outputAnalyser.smoothingTimeConstant = 0.8;
          
          this.outputGainNode.connect(this.outputAnalyser);
          this.outputAnalyser.connect(this.outputAudioCtx.destination);
          
          // Load the AudioWorklet module for microphone processing
          // Priority 1: Inline Blob URL (self-contained, instant, immune to path/network/Electron issues)
          // Priority 2: Static file fetch fallback (/audio-worklet-processor.js)
          let workletLoaded = false;
          if (this.inputAudioCtx.audioWorklet) {
            try {
              const workletBlob = new Blob([MIC_WORKLET_CODE], { type: "application/javascript" });
              const blobUrl = URL.createObjectURL(workletBlob);
              try {
                await this.inputAudioCtx.audioWorklet.addModule(blobUrl);
                workletLoaded = true;
              } finally {
                URL.revokeObjectURL(blobUrl);
              }
            } catch (blobError) {
              console.warn("Inline Blob AudioWorklet failed, trying static file fallback...", blobError);
              try {
                await this.inputAudioCtx.audioWorklet.addModule('/audio-worklet-processor.js');
                workletLoaded = true;
              } catch (staticError) {
                console.warn("Static AudioWorklet failed, will fall back to ScriptProcessorNode:", staticError);
              }
            }
          }
          
          // Obtain User Microphone stream
          const stream = await navigator.mediaDevices.getUserMedia({
            audio: {
              echoCancellation: true,
              noiseSuppression: true,
              autoGainControl: true,
            }
          });

          // Safeguard: Check if we disconnected while waiting for user to grant mic permissions
          if (!this.isActivated || !this.inputAudioCtx || !this.outputAudioCtx) {
            stream.getTracks().forEach((track) => {
              try {
                track.stop();
              } catch (e) {}
            });
            return;
          }

          this.micStream = stream;

          // Monitor microphone tracks for system mute, disconnect, or sleep events
          this.micStream.getAudioTracks().forEach((track) => {
            track.onmute = () => {
              console.warn("[Yashi Audio] Microphone track muted by hardware or system.");
            };
            track.onunmute = () => {
              console.log("[Yashi Audio] Microphone track unmuted.");
              if (this.inputAudioCtx && this.inputAudioCtx.state === "suspended") {
                this.inputAudioCtx.resume().catch(() => {});
              }
            };
            track.onended = () => {
              console.warn("[Yashi Audio] Microphone track ended unexpectedly, attempting refresh...");
              if (this.isActivated && !this.userInitiatedDisconnect) {
                this.refreshMicTrack().catch(() => {});
              }
            };
          });

          // Setup custom input Analyser
          this.inputAnalyser = this.inputAudioCtx.createAnalyser();
          this.inputAnalyser.fftSize = 256;
          
          this.micSourceNode = this.inputAudioCtx.createMediaStreamSource(this.micStream);
          this.micSourceNode.connect(this.inputAnalyser);

          const silentGainNode = this.inputAudioCtx.createGain();
          silentGainNode.gain.value = 0;

          if (workletLoaded) {
            try {
              this.micWorkletNode = new AudioWorkletNode(this.inputAudioCtx, 'yashi-mic-processor');
              this.micWorkletNode.port.onmessage = (event) => {
                if (this.currentState === "disconnected" || this.currentState === "connecting") return;
                const pcmBuffer = event.data;
                if (pcmBuffer && pcmBuffer.byteLength > 0) {
                  const base64 = int16ArrayBufferToBase64(pcmBuffer);
                  if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(JSON.stringify({ audio: base64 }));
                  }
                }
              };
              this.micSourceNode.connect(this.micWorkletNode);
              this.micWorkletNode.connect(silentGainNode);
              silentGainNode.connect(this.inputAudioCtx.destination);
            } catch (workletNodeErr) {
              console.warn("AudioWorkletNode instantiation failed, falling back to ScriptProcessorNode:", workletNodeErr);
              workletLoaded = false;
            }
          }

          if (!workletLoaded) {
            // High-compatibility ScriptProcessorNode fallback (works across all browsers and Electron environments)
            const bufferSize = 2048;
            const scriptNode = (this.inputAudioCtx.createScriptProcessor || (this.inputAudioCtx as any).createJavaScriptNode).call(
              this.inputAudioCtx,
              bufferSize,
              1,
              1
            );
            const sourceRate = this.inputAudioCtx.sampleRate;
            scriptNode.onaudioprocess = (e: AudioProcessingEvent) => {
              if (this.currentState === "disconnected" || this.currentState === "connecting") return;
              const inputBuffer = e.inputBuffer;
              const channelData = inputBuffer.getChannelData(0);
              let resampled: Float32Array;
              if (!sourceRate || sourceRate === 16000 || Math.abs(sourceRate - 16000) < 50) {
                resampled = channelData;
              } else {
                const ratio = sourceRate / 16000;
                const newLen = Math.round(channelData.length / ratio);
                resampled = new Float32Array(newLen);
                for (let i = 0; i < newLen; i++) {
                  const srcIdx = i * ratio;
                  const i0 = Math.floor(srcIdx);
                  const i1 = Math.min(i0 + 1, channelData.length - 1);
                  const frac = srcIdx - i0;
                  resampled[i] = channelData[i0] * (1 - frac) + channelData[i1] * frac;
                }
              }
              const pcmData = new Int16Array(resampled.length);
              for (let i = 0; i < resampled.length; i++) {
                const s = Math.max(-1, Math.min(1, resampled[i]));
                pcmData[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
              }
              const base64 = int16ArrayBufferToBase64(pcmData.buffer);
              if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({ audio: base64 }));
              }
            };
            this.micScriptNode = scriptNode;
            this.micSourceNode.connect(scriptNode);
            scriptNode.connect(silentGainNode);
            silentGainNode.connect(this.inputAudioCtx.destination);
          }

          // Sound setups are fully functional
          this.setState("listening");

          // Active watchdog: ensures AudioContexts never stay silently suspended after gaps in talking
          if (this.keepAliveTimer) clearInterval(this.keepAliveTimer);
          this.keepAliveTimer = setInterval(() => {
            if (!this.isActivated || this.userInitiatedDisconnect) return;
            if (this.inputAudioCtx && this.inputAudioCtx.state === "suspended") {
              this.inputAudioCtx.resume().catch(() => {});
            }
            if (this.outputAudioCtx && this.outputAudioCtx.state === "suspended") {
              this.outputAudioCtx.resume().catch(() => {});
            }
          }, 2000);

          // WebSocket heartbeat ping every 15s to keep connection alive during silence
          if (this.pingTimer) clearInterval(this.pingTimer);
          this.pingTimer = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
              this.ws.send(JSON.stringify({ type: "ping" }));
            }
          }, 15000);

        } catch (audioError: any) {
          console.error("Audio Context or Microphone Initialization Failed:", audioError);
          const isPermissionDenied = audioError.name === "NotAllowedError" ||
            audioError.name === "PermissionDeniedError" ||
            /permission|not allowed|denied/i.test(audioError.message || "");
          if (isPermissionDenied) {
            this.onError("Microphone access was denied. Please grant microphone permission in macOS System Settings > Privacy & Security > Microphone.");
          } else {
            this.onError(`Audio initialization error: ${audioError.message || "Failed to initialize microphone stream."}`);
          }
          this.disconnect();
        }
      };

      this.ws.onmessage = async (event) => {
        try {
          const data = JSON.parse(event.data);
          
          // Heartbeat response
          if (data.type === "pong") {
            return;
          }

          // Root Error Handler message
          if (data.type === "error") {
            this.onError(data.error);
            this.disconnect();
            return;
          }

          // Handle server-side states
          if (data.type === "status") {
            console.log("[Yashi WS Status]:", data.status);
            if (data.status === "connecting_gemini" || data.status === "reconnecting") {
              this.setState("connecting");
            } else if (data.status === "connected") {
              this.setState("listening");
            } else if (data.status === "session_closed") {
              if (this.userInitiatedDisconnect) {
                this.disconnect();
              }
            }
            return;
          }

          // Handle audio payload (24kHzPCM model response)
          if (data.type === "audio" && data.audio) {
            this.playAudioPCMChunk(data.audio);
          }

          // Handle interruption signal (e.g. user talked over Yashi)
          if (data.type === "interrupted") {
            this.handleInterruption();
          }

          // Turn complete
          if (data.type === "turnComplete") {
            // Once Yashi completes speaking, change visual state back to listening
            setTimeout(() => {
              if (this.activeSources.length === 0 && this.currentState === "speaking") {
                this.setState("listening");
              }
            }, 100);
          }

          // Handle live captions transcription
          if (data.type === "transcription") {
            this.onTranscription(data.role, data.text);
          }

          // Handle memory synchronization
          if (data.type === "memory_sync" && data.memories) {
            if (this.onMemorySync) {
              this.onMemorySync(data.memories);
            }
          }

          // Handle Tool Calling
          if (data.type === "toolCall") {
            const { callId, name, args } = data;
            this.onToolCall(name, args, (result) => {
              // Send back execution result to server bridge
              if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({
                  type: "toolResponse",
                  id: callId,
                  name: name,
                  output: result
                }));
              }
            });
          }

          // Sensitive action awaiting user approval
          if (data.type === "confirmationRequest" && data.id && data.message) {
            if (this.onConfirmationRequest) {
              this.onConfirmationRequest(data.id, data.message);
            }
          }

        } catch (parseError) {
          console.error("Error reading server packet:", parseError);
        }
      };

      this.ws.onerror = (wsError) => {
        console.error("WebSocket transport error:", wsError);
        if (!this.userInitiatedDisconnect) {
          this.onError("Holographic network link lost. Attempting to reconnect...");
          this.scheduleReconnect();
        } else {
          this.onError("Holographic network link lost. Please check connection.");
          this.disconnect();
        }
      };

      this.ws.onclose = () => {
        console.log("WebSocket connection closed");
        if (!this.userInitiatedDisconnect) {
          this.scheduleReconnect();
        } else {
          this.disconnect();
        }
      };

    } catch (e: any) {
      console.error("Connection establish sequence failed:", e);
      this.onError(e.message || "Failed to initialize active channel.");
      this.disconnect();
    }
  }

  // Interruption triggers: stops all active audio players immediately
  private handleInterruption() {
    console.log("[Audio] Interruption signal received; flushing play logs.");
    
    // Stop all playing nodes
    this.activeSources.forEach((source) => {
      try {
        source.stop();
      } catch (err) {
        // Already finished or stopped
      }
    });
    this.activeSources = [];
    this.nextStartTime = 0;
    
    // Set state back to user listening
    this.setState("listening");
  }

  // Direct raw PCM chunk scheduled playback at 24kHz
  private playAudioPCMChunk(base64Audio: string) {
    if (!this.outputAudioCtx || !this.outputGainNode) return;

    try {
      // Ensure output context is running so browser autoplay policy does not silence model voice
      if (this.outputAudioCtx.state === "suspended") {
        this.outputAudioCtx.resume().catch(() => {});
      }

      this.setState("speaking");
      const uint8Array = base64ToUint8Array(base64Audio);
      const floats = pcm16ToFloats(uint8Array);

      // Create AudioBuffer of 24000Hz (the exact playback sample rate of Gemini outputs)
      const buffer = this.outputAudioCtx.createBuffer(1, floats.length, 24000);
      buffer.getChannelData(0).set(floats);

      // Create Buffer source
      const source = this.outputAudioCtx.createBufferSource();
      source.buffer = buffer;

      // Connect source to gain which is routed to analyser & speakers
      source.connect(this.outputGainNode);

      const currentTime = this.outputAudioCtx.currentTime;
      
      // Gapless scheduler sync
      if (this.nextStartTime < currentTime) {
        // Start fresh: 30ms ahead to bridge schedule timing
        this.nextStartTime = currentTime + 0.03;
      }

      source.start(this.nextStartTime);
      this.nextStartTime += buffer.duration;

      // Keep reference to handle real-time interruptions
      source.onended = () => {
        const index = this.activeSources.indexOf(source);
        if (index > -1) {
          this.activeSources.splice(index, 1);
        }
        
        // If there are no more active play nodes, revert state back to listening
        if (this.activeSources.length === 0 && this.currentState === "speaking") {
          this.setState("listening");
        }
      };

      this.activeSources.push(source);

    } catch (playbackError) {
      console.error("PCM Chunk buffering/playback failed:", playbackError);
    }
  }

  // Fully cleanup and release microphones & connection sockets
  public disconnect() {
    this.userInitiatedDisconnect = true;
    this.isActivated = false;
    this.setState("disconnected");

    // Close WS socket
    if (this.ws) {
      try {
        this.ws.close();
      } catch (e) {}
      this.ws = null;
    }

    // Stop the AudioWorklet (send stop message to flush buffer)
    if (this.micWorkletNode) {
      try {
        this.micWorkletNode.port.postMessage('stop');
      } catch (e) {}
    }

    // Stop and release user microphone streams
    if (this.micStream) {
      this.micStream.getTracks().forEach((track) => {
        try {
          track.stop();
        } catch (e) {}
      });
      this.micStream = null;
    }

    // Disconnect routing nodes
    if (this.micWorkletNode) {
      try {
        this.micWorkletNode.disconnect();
      } catch (e) {}
      this.micWorkletNode = null;
    }

    if (this.micScriptNode) {
      try {
        this.micScriptNode.disconnect();
        this.micScriptNode.onaudioprocess = null;
      } catch (e) {}
      this.micScriptNode = null;
    }

    if (this.micSourceNode) {
      try {
        this.micSourceNode.disconnect();
      } catch (e) {}
      this.micSourceNode = null;
    }

    // Close Audio contexts
    if (this.inputAudioCtx) {
      try {
        this.inputAudioCtx.close();
      } catch (e) {}
      this.inputAudioCtx = null;
    }

    if (this.outputAudioCtx) {
      try {
        this.outputAudioCtx.close();
      } catch (e) {}
      this.outputAudioCtx = null;
    }

    this.activeSources = [];
    this.nextStartTime = 0;
    this.inputAnalyser = null;
    this.outputAnalyser = null;
    this.outputGainNode = null;

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    if (this.keepAliveTimer) {
      clearInterval(this.keepAliveTimer);
      this.keepAliveTimer = null;
    }
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  // Refresh mic track if hardware device changed or disconnected
  private async refreshMicTrack(): Promise<void> {
    if (!this.isActivated || this.userInitiatedDisconnect || !this.inputAudioCtx) return;
    try {
      console.log("[Yashi Audio] Re-requesting microphone track...");
      const newStream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
        }
      });
      if (this.micStream) {
        this.micStream.getTracks().forEach((t) => { try { t.stop(); } catch (e) {} });
      }
      this.micStream = newStream;
      if (this.inputAudioCtx && this.inputAudioCtx.state !== "closed") {
        if (this.micSourceNode) {
          try { this.micSourceNode.disconnect(); } catch (e) {}
        }
        this.micSourceNode = this.inputAudioCtx.createMediaStreamSource(this.micStream);
        if (this.inputAnalyser) {
          this.micSourceNode.connect(this.inputAnalyser);
        }
        if (this.micWorkletNode) {
          this.micSourceNode.connect(this.micWorkletNode);
        } else if (this.micScriptNode) {
          this.micSourceNode.connect(this.micScriptNode);
        }
        if (this.inputAudioCtx.state === "suspended") {
          await this.inputAudioCtx.resume().catch(() => {});
        }
      }
    } catch (err) {
      console.error("[Yashi Audio] Failed to refresh microphone track:", err);
    }
  }

  // Auto-reconnection with exponential backoff
  private scheduleReconnect(): void {
    if (this.userInitiatedDisconnect || this.reconnecting) return;
    
    this.reconnectAttempts++;
    if (this.reconnectAttempts > this.MAX_RECONNECT_ATTEMPTS) {
      console.error(`[Yashi] Max reconnect attempts (${this.MAX_RECONNECT_ATTEMPTS}) reached. Giving up.`);
      this.onError("Connection lost. Please refresh the page to restart.");
      this.disconnect();
      return;
    }
    
    this.reconnecting = true;
    const delayMs = Math.min(this.BASE_RECONNECT_DELAY_MS * 2 ** (this.reconnectAttempts - 1), 30000);
    console.log(`[Yashi] Scheduling reconnect attempt ${this.reconnectAttempts}/${this.MAX_RECONNECT_ATTEMPTS} in ${delayMs}ms`);
    this.onError(`Reconnecting... (attempt ${this.reconnectAttempts}/${this.MAX_RECONNECT_ATTEMPTS})`);
    
    this.reconnectTimer = setTimeout(() => {
      this.reconnecting = false;
      if (this.userInitiatedDisconnect) return;
      this.connect().catch((e) => {
        console.error("[Yashi] Reconnect attempt failed:", e);
        this.scheduleReconnect();
      });
    }, delayMs);
  }
}