/**
 * AudioWorkletProcessor for Yashi microphone capture.
 * Replaces deprecated ScriptProcessorNode for 16kHz PCM capture.
 * 
 * This runs on the audio rendering thread (not main thread) for low-latency processing.
 */

class YashiMicProcessor extends AudioWorkletProcessor {
  constructor(options) {
    super(options);
    this._bufferSize = 2048; // Match the old ScriptProcessorNode buffer size
    this._buffer = new Float32Array(this._bufferSize);
    this._bufferIndex = 0;
    this._port = this.port;
    
    // Handle messages from main thread
    this._port.onmessage = (event) => {
      if (event.data === 'stop') {
        this._flushBuffer();
      }
    };
  }

  process(inputs, outputs) {
    const input = inputs[0];
    if (input.length > 0) {
      const channelData = input[0]; // Mono input
      
      for (let i = 0; i < channelData.length; i++) {
        this._buffer[this._bufferIndex++] = channelData[i];
        
        if (this._bufferIndex >= this._bufferSize) {
          this._flushBuffer();
        }
      }
    }
    
    // Keep the processor alive
    return true;
  }

  _flushBuffer() {
    if (this._bufferIndex > 0) {
      // Convert Float32 to Int16 PCM
      const pcmData = new Int16Array(this._bufferIndex);
      for (let i = 0; i < this._bufferIndex; i++) {
        const s = Math.max(-1, Math.min(1, this._buffer[i]));
        pcmData[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
      }
      
      // Send to main thread via MessagePort (transfer ownership for efficiency)
      this._port.postMessage(pcmData.buffer, [pcmData.buffer]);
      
      this._bufferIndex = 0;
    }
  }
}

registerProcessor('yashi-mic-processor', YashiMicProcessor);
try {
  registerProcessor('vexa-mic-processor', YashiMicProcessor);
} catch {}