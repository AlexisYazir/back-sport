/* eslint-disable */
import { ConfigService } from '@nestjs/config';
import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { Transporter } from 'nodemailer';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  constructor(private readonly configService: ConfigService) {}

  private createTransporter(): Transporter {
    return nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: this.configService.getOrThrow<string>('EMAIL_USER'),
        pass: this.configService.getOrThrow<string>('EMAIL_PASS'),
      },
    });
  }

  //! funcion para enviar correo de activacion de cuenta
  public async sendVerificationEmail(email: string, nombre: string, token: string, ): Promise<void> {
    const transporter = this.createTransporter();

    const url = token;

    const mailOptions = {
      from: `"Sport Center" <${this.configService.get<string>('EMAIL_USER')}>`,
      to: email,
      subject: 'Activa tu cuenta',
      html: `
      <h2>¡Bienvenido a Sport Center, ${nombre}!</h2>
      <p>Gracias por registrarte con nosotros. Tu cuenta ya esta casi lista.</p>
      <p>Este es tu codigo de verificación para activar tu cuenta:</p> </br>
      <h1>${url}</h1>
      <p>Este código expirará en 24 horas.</p>
      <p>Si no fuiste tú quien creó esta cuenta, puedes ignorar este mensaje sin problema.</p>
  
  <p>Saludos cordiales<br>
  <b>Sport Center</b></p>
    `,
    };

    try {
      await transporter.sendMail(mailOptions);
      this.logger.log(`Correo enviado: ${email}`);
    } catch (error) {
      if (error instanceof Error) {
        console.error('Error al enviar correo:', error.message);
      } else {
        console.error('Error desconocido al enviar correo');
      }
    }
  }

  //! funcion para enviar correo de activacion de cuenta
  public async resendVerificationEmail(
    email: string,
    nombre: string,
    token: string,
  ): Promise<void> {
    const transporter = this.createTransporter();

    const url = token;

    const mailOptions = {
      from: `"Sport Center" <${this.configService.get<string>('EMAIL_USER')}>`,
      to: email,
      subject: 'Activa tu cuenta',
      html: `
      <h2>¡Hola de nuevo, ${nombre}!</h2>
      <p>Este es tu nuevo codigo de verificación para activar tu cuenta:</p> </br>
      <h1>${url}</h1>
      <p>Este código expirará en 24 horas.</p>
      <p>Si no fuiste tú quien solitito este codigo, puedes ignorar este mensaje sin problema.</p>
  
  <p>Saludos cordiales,<br>
  <b>Sport Center</b></p>
    `,
    };

    try {
      await transporter.sendMail(mailOptions);
      this.logger.log(`Correo enviado: ${email}`);
    } catch (error) {
      if (error instanceof Error) {
        console.error('Error al enviar correo:', error.message);
      } else {
        console.error('Error desconocido al enviar correo');
      }
    }
  }

  //! funcion para enviar correo de token de recuperacion de contraseña
  public async sendRecoveryEmail(
    email: string,
    nombre: string,
    token: string,
  ): Promise<void> {
    const transporter = this.createTransporter();

    const mailOptions = {
      from: `"Sport Center" <${this.configService.get<string>('EMAIL_USER')}>`,
      to: email,
      subject: 'Recuperación de contraseña',
      html: `
      <h2>Hola ${nombre} !</h2>
      <p>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta.</p>
      <p>Tu token de recuperación (expira en 24 horas):</p>
      <h3>${token}</h3>

      <br>
      <p>Saludos cordiales,<br><b>Sport Center</b></p>
    `,
    };

    await transporter.sendMail(mailOptions);
  }

  public async sendCriticalAlertEmail(
    email: string,
    subject: string,
    html: string,
  ): Promise<void> {
    const transporter = this.createTransporter();

    await transporter.sendMail({
      from: `"Sport Center" <${this.configService.get<string>('EMAIL_USER')}>`,
      to: email,
      subject,
      html,
    });
  }
}
