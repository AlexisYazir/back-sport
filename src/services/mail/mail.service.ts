/* eslint-disable */
import { ConfigService } from '@nestjs/config';
import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { Transporter } from 'nodemailer';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  constructor(private readonly configService: ConfigService) {}

  private get resendApiKey(): string | undefined {
    return this.configService.get<string>('RESEND_API_KEY')?.trim();
  }

  private get senderEmail(): string {
    return (
      this.configService.get<string>('RESEND_FROM_EMAIL')?.trim() ||
      this.configService.get<string>('EMAIL_USER')?.trim() ||
      'onboarding@resend.dev'
    );
  }

  private createTransporter(): Transporter {
    return nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: this.configService.getOrThrow<string>('EMAIL_USER'),
        pass: this.configService.getOrThrow<string>('EMAIL_PASS'),
      },
    });
  }

  private async sendEmail(
    email: string,
    subject: string,
    html: string,
  ): Promise<void> {
    if (this.resendApiKey) {
      await this.sendWithResend(email, subject, html);
      return;
    }

    await this.sendWithGmail(email, subject, html);
  }

  private async sendWithGmail(
    email: string,
    subject: string,
    html: string,
  ): Promise<void> {
    const transporter = this.createTransporter();

    await transporter.sendMail({
      from: `"Sport Center" <${this.senderEmail}>`,
      to: email,
      subject,
      html,
    });
  }

  private async sendWithResend(
    email: string,
    subject: string,
    html: string,
  ): Promise<void> {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.resendApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: `Sport Center <${this.senderEmail}>`,
        to: [email],
        subject,
        html,
      }),
    });

    if (!response.ok) {
      const responseText = await response.text();
      this.logger.error(
        `Resend respondio ${response.status}: ${responseText}`,
      );
      throw new Error(`Resend error ${response.status}: ${responseText}`);
    }
  }

  //! funcion para enviar correo de activacion de cuenta
  public async sendVerificationEmail(email: string, nombre: string, token: string, ): Promise<void> {
    const url = token;

    const subject = 'Activa tu cuenta';
    const html = `
      <h2>¡Bienvenido a Sport Center, ${nombre}!</h2>
      <p>Gracias por registrarte con nosotros. Tu cuenta ya esta casi lista.</p>
      <p>Este es tu codigo de verificación para activar tu cuenta:</p> </br>
      <h1>${url}</h1>
      <p>Este código expirará en 24 horas.</p>
      <p>Si no fuiste tú quien creó esta cuenta, puedes ignorar este mensaje sin problema.</p>
  
  <p>Saludos cordiales<br>
  <b>Sport Center</b></p>
    `;

    try {
      await this.sendEmail(email, subject, html);
      this.logger.log(`Correo enviado: ${email}`);
    } catch (error) {
      if (error instanceof Error) {
        this.logger.error(`Error al enviar correo a ${email}: ${error.message}`);
      } else {
        this.logger.error(`Error desconocido al enviar correo a ${email}`);
      }
      throw error;
    }
  }

  //! funcion para enviar correo de activacion de cuenta
  public async resendVerificationEmail(
    email: string,
    nombre: string,
    token: string,
  ): Promise<void> {
    const url = token;

    const subject = 'Activa tu cuenta';
    const html = `
      <h2>¡Hola de nuevo, ${nombre}!</h2>
      <p>Este es tu nuevo codigo de verificación para activar tu cuenta:</p> </br>
      <h1>${url}</h1>
      <p>Este código expirará en 24 horas.</p>
      <p>Si no fuiste tú quien solitito este codigo, puedes ignorar este mensaje sin problema.</p>
  
  <p>Saludos cordiales,<br>
  <b>Sport Center</b></p>
    `;

    try {
      await this.sendEmail(email, subject, html);
      this.logger.log(`Correo enviado: ${email}`);
    } catch (error) {
      if (error instanceof Error) {
        this.logger.error(`Error al reenviar correo a ${email}: ${error.message}`);
      } else {
        this.logger.error(`Error desconocido al reenviar correo a ${email}`);
      }
      throw error;
    }
  }

  //! funcion para enviar correo de token de recuperacion de contraseña
  public async sendRecoveryEmail(
    email: string,
    nombre: string,
    token: string,
  ): Promise<void> {
    const subject = 'Recuperación de contraseña';
    const html = `
      <h2>Hola ${nombre} !</h2>
      <p>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta.</p>
      <p>Tu token de recuperación (expira en 24 horas):</p>
      <h3>${token}</h3>

      <br>
      <p>Saludos cordiales,<br><b>Sport Center</b></p>
    `;

    await this.sendEmail(email, subject, html);
  }

  public async sendCriticalAlertEmail(
    email: string,
    subject: string,
    html: string,
  ): Promise<void> {
    await this.sendEmail(email, subject, html);
  }
}
