import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';

export interface CloudinaryUploadResult {
  public_id: string;
  secure_url: string;
  url: string;
  bytes: number;
  format: string;
  original_filename: string;
  resource_type: string;
}

@Injectable()
export class CloudinaryService {
  constructor(private readonly configService: ConfigService) {}

  async uploadProductImage(
    file: Express.Multer.File,
    folder?: string,
  ): Promise<CloudinaryUploadResult> {
    if (!file) {
      throw new BadRequestException('No se recibio ningun archivo');
    }

    const cloudName = this.configService.get<string>('CLOUDINARY_CLOUD_NAME');
    const apiKey = this.configService.get<string>('CLOUDINARY_API_KEY');
    const apiSecret = this.configService.get<string>('CLOUDINARY_API_SECRET');
    const defaultFolder =
      this.configService.get<string>('CLOUDINARY_UPLOAD_FOLDER') ||
      'sport-center/products';

    if (!cloudName || !apiKey || !apiSecret) {
      throw new BadRequestException(
        'Cloudinary no esta configurado en el servidor',
      );
    }

    const dataUri = `data:${file.mimetype};base64,${file.buffer.toString('base64')}`;
    const body = new URLSearchParams();
    body.append('file', dataUri);
    body.append('folder', folder?.trim() || defaultFolder);
    body.append('use_filename', 'true');
    body.append('unique_filename', 'true');

    const response = await axios.post<CloudinaryUploadResult>(
      `https://api.cloudinary.com/v1_1/${cloudName}/image/upload`,
      body,
      {
        auth: {
          username: apiKey,
          password: apiSecret,
        },
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        maxBodyLength: Infinity,
      },
    );

    return response.data;
  }
}
