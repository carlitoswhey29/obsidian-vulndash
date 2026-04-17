export interface VirtualViewportState {
  scrollTop: number;
  viewportHeight: number;
  viewportWidth: number;
}

export interface VirtualViewportOptions {
  onChange: (state: VirtualViewportState) => void;
}

export class VirtualViewport {
  private animationFrameId: number | null = null;
  private lastState: VirtualViewportState | null = null;
  private resizeObserver: ResizeObserver | null = null;
  private scrollEl: HTMLElement | null = null;

  public constructor(
    private readonly options: VirtualViewportOptions
  ) {}

  public bind(scrollEl: HTMLElement): void {
    if (this.scrollEl === scrollEl) {
      this.refresh();
      return;
    }

    this.destroyBindings();
    this.scrollEl = scrollEl;
    this.lastState = null;
    scrollEl.addEventListener('scroll', this.handleScroll, { passive: true });

    if (typeof ResizeObserver !== 'undefined') {
      this.resizeObserver = new ResizeObserver(() => {
        this.scheduleEmit();
      });
      this.resizeObserver.observe(scrollEl);
    } else {
      window.addEventListener('resize', this.handleResize);
    }

    this.refresh();
  }

  public refresh(): void {
    this.scheduleEmit();
  }

  public destroy(): void {
    this.destroyBindings();
  }

  private destroyBindings(): void {
    if (this.animationFrameId !== null) {
      window.cancelAnimationFrame(this.animationFrameId);
      this.animationFrameId = null;
    }

    if (this.scrollEl) {
      this.scrollEl.removeEventListener('scroll', this.handleScroll);
    }

    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
      this.resizeObserver = null;
    } else {
      window.removeEventListener('resize', this.handleResize);
    }

    this.scrollEl = null;
    this.lastState = null;
  }

  private readonly handleResize = (): void => {
    this.scheduleEmit();
  };

  private readonly handleScroll = (): void => {
    this.scheduleEmit();
  };

  private scheduleEmit(): void {
    if (this.animationFrameId !== null) {
      return;
    }

    this.animationFrameId = window.requestAnimationFrame(() => {
      this.animationFrameId = null;
      this.emitIfChanged();
    });
  }

  private emitIfChanged(): void {
    if (!this.scrollEl) {
      return;
    }

    const nextState: VirtualViewportState = {
      scrollTop: this.scrollEl.scrollTop,
      viewportHeight: this.scrollEl.clientHeight,
      viewportWidth: this.scrollEl.clientWidth
    };

    if (
      this.lastState
      && this.lastState.scrollTop === nextState.scrollTop
      && this.lastState.viewportHeight === nextState.viewportHeight
      && this.lastState.viewportWidth === nextState.viewportWidth
    ) {
      return;
    }

    this.lastState = nextState;
    this.options.onChange(nextState);
  }
}
