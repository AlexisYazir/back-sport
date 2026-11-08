import {
  Injectable,
  OnModuleDestroy,
  OnModuleInit,
  Logger,
} from '@nestjs/common';
import { DeletionRecoveryGate } from './deletion-recovery-gate';
import { AccountDeletionService } from './account-deletion.service';

@Injectable()
export class AccountDeletionBootstrapService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(AccountDeletionBootstrapService.name);
  private timer: ReturnType<typeof setInterval> | undefined;
  private running = false;
  constructor(
    private readonly gate: DeletionRecoveryGate,
    private readonly service: AccountDeletionService,
  ) {}
  async prepare(): Promise<void> {
    this.service.validateConfiguration();
    try {
      await this.gate.reconcileBeforeServing((intent) =>
        this.service.replay(intent),
      );
      if (this.gate.enabled) await this.service.expireRetainedRecords();
    } catch (error) {
      this.gate.invalidate();
      throw error;
    }
  }
  onModuleInit(): void {
    // Main and serverless entrypoints call prepare before ANY onModuleInit jobs.
    this.gate.assertApplicationReady();
    if (!this.gate.enabled) return;
    this.timer = setInterval(() => {
      void this.tick();
    }, 60_000);
    this.timer.unref();
  }
  private async tick(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      this.gate.assertDeletionReady();
      await this.service.expireRetainedRecords();
      await this.service.retryNotifications();
    } catch {
      this.logger.error('Account deletion maintenance requires attention');
    } finally {
      this.running = false;
    }
  }
  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }
}
