import { Request, Response, NextFunction } from 'express';

export interface MADPSAgentOptions {
  /**
   * MAD-PS Organization Live API Key (e.g. 'mk_live_...')
   */
  apiKey: string;

  /**
   * MAD-PS Ingestion Gateway URL
   * @default 'http://127.0.0.1:8000/api/v1/ingest/log'
   */
  endpoint?: string;

  /**
   * Request timeout for background telemetry post in ms
   * @default 1500
   */
  timeoutMs?: number;

  /**
   * Enable verbose debug logging in console
   * @default false
   */
  debug?: boolean;

  /**
   * Custom route paths or RegExp patterns to ignore
   */
  excludePaths?: Array<string | RegExp>;

  /**
   * Custom set of header names to redact
   */
  redactHeaders?: Set<string>;
}

export declare class CircuitBreaker {
  constructor(options?: { threshold?: number; resetTimeoutMs?: number });
  recordSuccess(): void;
  recordFailure(): void;
  canAttempt(): boolean;
  isOpen: boolean;
}

export declare function madpsAgent(options: MADPSAgentOptions): (req: Request, res: Response, next: NextFunction) => void;
export default madpsAgent;
