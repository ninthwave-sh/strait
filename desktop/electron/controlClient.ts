import path from 'node:path';
import os from 'node:os';
import { EventEmitter } from 'node:events';

import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';

import type {
  BlockedRequestSummary,
  DecisionAction,
  DesktopSnapshot,
  SessionSummary,
  SubmitDecisionInput,
  SubmitDecisionResult
} from '../src/types';

type GrpcClient = grpc.Client & {
  listSessions(request: Record<string, never>, callback: (error: grpc.ServiceError | null, response: any) => void): void;
  streamBlockedRequests(request: { sessionId: string }): grpc.ClientReadableStream<any>;
  submitDecision(request: any, callback: (error: grpc.ServiceError | null, response: any) => void): void;
};

function defaultRuntimeDir(): string {
  if (process.env.XDG_RUNTIME_DIR) {
    return path.join(process.env.XDG_RUNTIME_DIR, 'strait');
  }
  if (process.env.HOME) {
    return path.join(process.env.HOME, '.local', 'state', 'strait', 'runtime');
  }
  const uid = typeof process.getuid === 'function' ? process.getuid() : 'unknown';
  return path.join(os.tmpdir(), `strait-${uid}`);
}

function defaultSocketPath(): string {
  return process.env.STRAIT_CONTROL_SOCKET ?? path.join(defaultRuntimeDir(), 'control-service.sock');
}

function grpcTarget(socketPath: string): string {
  return `unix:${socketPath}`;
}

function normalizeSession(session: any): SessionSummary {
  return {
    sessionId: session.sessionId ?? session.session_id ?? '',
    mode: session.mode ?? '',
    control: session.control
      ? {
          network: session.control.network ?? '',
          address: session.control.address ?? ''
        }
      : undefined,
    observation: session.observation
      ? {
          network: session.observation.network ?? '',
          address: session.observation.address ?? ''
        }
      : undefined,
    containerId: session.containerId ?? session.container_id ?? '',
    containerName: session.containerName ?? session.container_name ?? ''
  };
}

function normalizeBlockedRequest(event: any): BlockedRequestSummary {
  return {
    sessionId: event.session?.sessionId ?? event.session?.session_id ?? '',
    blockedId: event.blockedId ?? event.blocked_id ?? '',
    matchKey: event.matchKey ?? event.match_key ?? '',
    sourceType: event.sourceType ?? event.source_type ?? '',
    explanation: event.explanation ?? '',
    method: event.method ?? '',
    host: event.host ?? '',
    path: event.path ?? '',
    decision: event.decision ?? '',
    suggestions: (event.suggestions ?? []).map((suggestion: any) => ({
      lifetime: suggestion.lifetime ?? '',
      summary: suggestion.summary ?? '',
      cedarSnippet: suggestion.cedarSnippet ?? suggestion.cedar_snippet ?? '',
      scope: suggestion.scope ?? '',
      ambiguous: Boolean(suggestion.ambiguous)
    })),
    rawJson: event.rawJson ?? event.raw_json ?? '',
    observedAt: event.observedAt ?? event.observed_at ?? '',
    holdTimeoutSecs: Number(event.holdTimeoutSecs ?? event.hold_timeout_secs ?? 0),
    holdExpiresAt: event.holdExpiresAt ?? event.hold_expires_at ?? ''
  };
}

function decisionActionValue(action: DecisionAction): number {
  switch (action) {
    case 'deny':
      return 1;
    case 'allowOnce':
      return 2;
    case 'allowSession':
      return 3;
    case 'persist':
      return 4;
    case 'allowTtl':
      return 5;
  }
}

function loadServiceClient(socketPath: string): GrpcClient {
  const definition = protoLoader.loadSync(path.resolve(__dirname, '../../proto/control.proto'), {
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  });
  const proto = grpc.loadPackageDefinition(definition) as any;
  const Client = proto.strait.control.v1.SessionControlService as new (
    address: string,
    credentials: grpc.ChannelCredentials
  ) => GrpcClient;
  return new Client(grpcTarget(socketPath), grpc.credentials.createInsecure());
}

export class ControlPlane extends EventEmitter {
  private snapshot: DesktopSnapshot = {
    enabled: true,
    connected: false,
    serviceSocketPath: defaultSocketPath(),
    sessions: [],
    blockedRequests: [],
    lastError: null
  };

  private pollTimer: NodeJS.Timeout | null = null;
  private streams = new Map<string, grpc.ClientReadableStream<any>>();
  private client: GrpcClient | null = null;
  private clientSocketPath: string | null = null;

  private getClient(): GrpcClient {
    const socketPath = this.snapshot.serviceSocketPath;
    if (this.client && this.clientSocketPath === socketPath) {
      return this.client;
    }
    if (this.client) {
      this.client.close();
    }
    this.client = loadServiceClient(socketPath);
    this.clientSocketPath = socketPath;
    return this.client;
  }

  getSnapshot(): DesktopSnapshot {
    return JSON.parse(JSON.stringify(this.snapshot)) as DesktopSnapshot;
  }

  start() {
    this.emitState();
    this.schedulePolling();
  }

  setEnabled(enabled: boolean) {
    this.snapshot.enabled = enabled;
    if (!enabled) {
      this.stopStreams();
      this.snapshot.connected = false;
      if (this.pollTimer) {
        clearInterval(this.pollTimer);
        this.pollTimer = null;
      }
    } else {
      this.schedulePolling();
    }
    this.emitState();
  }

  async submitDecision(input: SubmitDecisionInput): Promise<SubmitDecisionResult> {
    const client = this.getClient();
    const resolvedBlockedIds: string[] = [];

    try {
      for (const blockedId of input.blockedIds) {
        await new Promise<void>((resolve, reject) => {
          client.submitDecision(
            {
              sessionId: input.sessionId,
              blockedId,
              action: decisionActionValue(input.action),
              ttlSeconds: input.ttlSeconds ?? 0
            },
            (error) => {
              if (error) {
                reject(error);
                return;
              }
              resolvedBlockedIds.push(blockedId);
              resolve();
            }
          );
        });
      }
    } finally {
      if (resolvedBlockedIds.length > 0) {
        this.snapshot.blockedRequests = this.snapshot.blockedRequests.filter(
          (request) => !resolvedBlockedIds.includes(request.blockedId)
        );
        this.emitState();
      }
    }

    return { resolvedBlockedIds };
  }

  stop() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    this.stopStreams();
    if (this.client) {
      this.client.close();
      this.client = null;
      this.clientSocketPath = null;
    }
  }

  private schedulePolling() {
    if (this.pollTimer || !this.snapshot.enabled) {
      return;
    }
    void this.pollSessions();
    this.pollTimer = setInterval(() => {
      void this.pollSessions();
    }, 2000);
  }

  private async pollSessions() {
    if (!this.snapshot.enabled) {
      return;
    }
    try {
      const sessions = await this.listSessions();
      this.snapshot.connected = true;
      this.snapshot.lastError = null;
      this.snapshot.sessions = sessions;
      this.reconcileStreams(sessions);
    } catch (error) {
      this.snapshot.connected = false;
      this.snapshot.lastError = error instanceof Error ? error.message : String(error);
      this.stopStreams();
    }
    this.emitState();
  }

  private async listSessions(): Promise<SessionSummary[]> {
    const client = this.getClient();
    return new Promise<SessionSummary[]>((resolve, reject) => {
      client.listSessions({}, (error, response) => {
        if (error) {
          reject(error);
          return;
        }
        resolve((response.sessions ?? []).map(normalizeSession));
      });
    });
  }

  private reconcileStreams(sessions: SessionSummary[]) {
    const liveSessionIds = new Set(sessions.map((session) => session.sessionId));

    for (const [sessionId, stream] of this.streams) {
      if (!liveSessionIds.has(sessionId)) {
        stream.cancel();
        this.streams.delete(sessionId);
      }
    }

    for (const session of sessions) {
      if (!this.streams.has(session.sessionId)) {
        this.startBlockedStream(session.sessionId);
      }
    }
  }

  private startBlockedStream(sessionId: string) {
    const client = this.getClient();
    const stream = client.streamBlockedRequests({ sessionId });
    this.streams.set(sessionId, stream);

    stream.on('data', (event) => {
      const blocked = normalizeBlockedRequest(event);
      if (!blocked.blockedId) {
        return;
      }
      if (this.snapshot.blockedRequests.some((request) => request.blockedId === blocked.blockedId)) {
        return;
      }
      this.snapshot.blockedRequests = [...this.snapshot.blockedRequests, blocked].slice(-200);
      this.emitState();
    });

    const closeStream = (error?: grpc.ServiceError) => {
      this.streams.delete(sessionId);
      if (error) {
        this.snapshot.connected = false;
        this.snapshot.lastError = error.message;
        this.emitState();
      }
    };

    stream.on('error', closeStream);
    stream.on('end', () => closeStream());
    stream.on('close', () => closeStream());
  }

  private stopStreams() {
    for (const stream of this.streams.values()) {
      stream.cancel();
    }
    this.streams.clear();
  }

  private emitState() {
    this.emit('state', this.getSnapshot());
  }
}
