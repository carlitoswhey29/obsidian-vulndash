export class ClientValidationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'ClientValidationError';
  }
}

export class ClientRateLimitError extends Error {
  public constructor(
    message: string,
    public readonly retryAfterSeconds?: number
  ) {
    super(message);
    this.name = 'ClientRateLimitError';
  }
}

export class ClientTransportError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'ClientTransportError';
  }
}
