import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import * as dotenv from 'dotenv';
dotenv.config();

@Injectable()
export class NodemailerService {
  private transporter: nodemailer.Transporter;

  constructor() {
    const mailHost = process.env.MAIL_HOST;
    const mailPort = parseInt(process.env.EMAIL_PORT || '587', 10);
    const mailUser = process.env.EMAIL_HOST_USER;
    const mailPass = process.env.EMAIL_HOST_PASSWORD;
    const mailFrom = process.env.EMAIL_FROM;

    if (!mailHost || !mailUser || !mailPass || !mailPort || !mailFrom) {
      throw new Error('Missing required email environment variables');
    }

    this.transporter = nodemailer.createTransport({
      host: mailHost,
      port: mailPort,
      secure: false, // Use TLS
      auth: {
        user: mailUser,
        pass: mailPass,
      },
    });
  }

  async sendMail(to: string, subject: string, text: string, html?: string): Promise<void> {
    try {
      console.log('--->',process.env.EMAIL_HOST_USER);
      const mailOptions = {
        from: process.env.EMAIL_FROM,
        to,
        subject,
        text,
        html,
      };
      const info = await this.transporter.sendMail(mailOptions);
      console.log('Email sent: ', info.messageId);
    } catch (error) {
      console.error('Failed to send email:', error.message);
      throw error;
    }
  }
}
