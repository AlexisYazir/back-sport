import type { Request } from 'express';

export interface AuthenticatedUser {
  id_usuario: number;
  email: string;
  nombre: string;
  rol: number;
  sessionId: string;
}

export interface AuthenticatedRequest extends Request {
  user: AuthenticatedUser;
}
