/* eslint-disable */
import { ConfigService } from '@nestjs/config';
import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { Transporter } from 'nodemailer';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  constructor(private readonly configService: ConfigService) {}

  private get brevoApiKey(): string | undefined {
    return this.configService.get<string>('BREVO_API_KEY')?.trim();
  }

  private get resendApiKey(): string | undefined {
    return this.configService.get<string>('RESEND_API_KEY')?.trim();
  }

  private get senderName(): string {
    return (
      this.configService.get<string>('BREVO_FROM_NAME')?.trim() ||
      this.configService.get<string>('EMAIL_FROM_NAME')?.trim() ||
      'Sport Center'
    );
  }

  private get senderEmail(): string {
    return (
      this.configService.get<string>('BREVO_FROM_EMAIL')?.trim() ||
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
    if (this.brevoApiKey) {
      await this.sendWithBrevo(email, subject, html);
      return;
    }

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
      from: `"${this.senderName}" <${this.senderEmail}>`,
      to: email,
      subject,
      html,
    });
  }

  private async sendWithBrevo(
    email: string,
    subject: string,
    html: string,
  ): Promise<void> {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'api-key': this.brevoApiKey || '',
      },
      body: JSON.stringify({
        sender: {
          name: this.senderName,
          email: this.senderEmail,
        },
        to: [{ email }],
        subject,
        htmlContent: html,
      }),
    });

    if (!response.ok) {
      const responseText = await response.text();
      this.logger.error(
        `Brevo respondio ${response.status}: ${responseText}`,
      );
      throw new Error(`Brevo error ${response.status}: ${responseText}`);
    }
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
        from: `${this.senderName} <${this.senderEmail}>`,
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
    expirationText = '24 horas',
  ): Promise<void> {
    const url = token;

    const subject = 'Activa tu cuenta';
    const html = `
      <h2>¡Hola de nuevo, ${nombre}!</h2>
      <p>Este es tu nuevo codigo de verificación para activar tu cuenta:</p> </br>
      <h1>${url}</h1>
      <p>Este código expirará en ${expirationText}.</p>
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

   //! funcion para enviar correo de activacion de cuenta
  public async requestVerificationCodeLogin (
    email: string,
    nombre: string,
    token: string,
    expirationText = '15 minutos',
  ): Promise<void> {
    const url = token;

    const subject = 'Codigo de verificación para iniciar sesión en alexa';
    const html = `
      <h2>¡Hola de nuevo, ${nombre}!</h2>
      <p>Este es tu codigo de verificación para iniciar sesión en Asistente Sport Center:</p> </br>
      <h1>${url}</h1>
      <p>Este código expirará en ${expirationText}.</p>
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

  public async sendCriticalAlertEmail(
    email: string,
    subject: string,
    html: string,
  ): Promise<void> {
    await this.sendEmail(email, subject, html);
  }

  public async sendOrderPaymentConfirmedEmail(
    email: string,
    nombre: string,
    order: any,
  ): Promise<void> {
    const subject = `Pago confirmado - Pedido #${order.id_orden}`;
    const html = this.buildOrderEmailTemplate({
      title: 'Pago confirmado',
      greeting: `Hola ${nombre || 'Cliente'},`,
      message:
        'Recibimos correctamente tu pago. Tu pedido ya fue registrado y pronto comenzará su preparación.',
      order,
    });

    await this.sendEmail(email, subject, html);
  }

  public async sendOrderStatusEmail(
    email: string,
    nombre: string,
    order: any,
    statusLabel: string,
    description: string,
  ): Promise<void> {
    const subject = `${statusLabel} - Pedido #${order.id_orden}`;
    const html = this.buildOrderEmailTemplate({
      title: statusLabel,
      greeting: `Hola ${nombre || 'Cliente'},`,
      message: description || 'Tu pedido tuvo una actualización.',
      order,
    });

    await this.sendEmail(email, subject, html);
  }

  public async sendOrderDeliveredEmail(
    email: string,
    nombre: string,
    order: any,
  ): Promise<void> {
    const subject = `Pedido recibido - #${order.id_orden}`;
    const html = this.buildOrderEmailTemplate({
      title: 'Pedido recibido',
      greeting: `Hola ${nombre || 'Cliente'},`,
      message:
        'Tu pedido fue validado como recibido. Gracias por comprar en Sport Center.',
      order,
    });

    await this.sendEmail(email, subject, html);
  }

  private buildOrderEmailTemplate(input: {
    title: string;
    greeting: string;
    message: string;
    order: any;
  }): string {
    const items = Array.isArray(input.order?.items) ? input.order.items : [];
    const itemsHtml = items
      .slice(0, 6)
      .map(
        (item: any) => `
          <tr>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;">${this.escapeHtml(item.producto || 'Producto')}</td>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;text-align:center;">${Number(item.cantidad || 0)}</td>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;text-align:right;">${this.formatMoney(item.total)}</td>
          </tr>
        `,
      )
      .join('');

    return `
      <div style="font-family:Arial,sans-serif;color:#202020;line-height:1.5;">
        <h2 style="color:#0367A6;margin-bottom:8px;">${this.escapeHtml(input.title)}</h2>
        <p>${this.escapeHtml(input.greeting)}</p>
        <p>${this.escapeHtml(input.message)}</p>
        <div style="background:#f8fafc;border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin:18px 0;">
          <p style="margin:0 0 6px;"><b>Pedido:</b> #${input.order?.id_orden || ''}</p>
          <p style="margin:0 0 6px;"><b>Total:</b> ${this.formatMoney(input.order?.total)}</p>
          <p style="margin:0 0 6px;"><b>Estado:</b> ${this.escapeHtml(input.order?.estado_envio || input.order?.estado || 'Actualizado')}</p>
          ${input.order?.paqueteria ? `<p style="margin:0 0 6px;"><b>Paquetería:</b> ${this.escapeHtml(input.order.paqueteria)}</p>` : ''}
          ${input.order?.tracking_number ? `<p style="margin:0;"><b>Guía:</b> ${this.escapeHtml(input.order.tracking_number)}</p>` : ''}
        </div>
        ${
          itemsHtml
            ? `<table style="width:100%;border-collapse:collapse;margin-top:12px;">
                <thead>
                  <tr style="background:#eef6fc;">
                    <th style="padding:10px;text-align:left;">Producto</th>
                    <th style="padding:10px;text-align:center;">Cantidad</th>
                    <th style="padding:10px;text-align:right;">Total</th>
                  </tr>
                </thead>
                <tbody>${itemsHtml}</tbody>
              </table>`
            : ''
        }
        <p style="margin-top:20px;">Saludos cordiales,<br><b>Sport Center</b></p>
      </div>
    `;
  }

  private formatMoney(value: any): string {
    return Number(value || 0).toLocaleString('es-MX', {
      style: 'currency',
      currency: 'MXN',
    });
  }

  private escapeHtml(value: any): string {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

}
