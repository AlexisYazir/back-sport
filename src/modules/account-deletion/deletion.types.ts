export const DELETION_STATUSES = [
  'received',
  'identity_verified',
  'deletion_confirmed',
  'in_progress',
  'completed',
  'requires_attention',
  'error',
] as const;
export type DeletionStatus = (typeof DELETION_STATUSES)[number];
export interface DeletionPrincipal {
  id_usuario: number;
  sessionId: string;
  rol: number;
}
export interface DeletionResult {
  requestId: string;
  status: DeletionStatus;
  reason: string | null;
  retainedCategories: string[];
  notification: 'pending' | 'sent' | 'not_required' | 'unavailable';
  retention?: { until: string; basis: string; identifiersExpired: boolean };
}
export interface DeletionRequest {
  request_id: string;
  user_id: number;
  account_id: string;
  session_id: string;
  status: DeletionStatus;
  reason: string | null;
  email_hash: string | null;
  code_hash: string | null;
  code_expires_at: Date | null;
  attempts: number;
  authorization_hash: string | null;
  authorization_expires_at: Date | null;
  receipt_hash: string;
  receipt_expires_at: Date;
  requested_at: Date;
  updated_at: Date;
  retained_categories: string[];
  notification_status: 'pending' | 'sent' | 'not_required' | 'unavailable';
  retain_until?: Date;
  retention_basis?: string;
  identifiers_expired_at?: Date | null;
  account_state?: string;
}
