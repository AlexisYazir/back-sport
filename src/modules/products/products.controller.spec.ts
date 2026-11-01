import { BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Readable } from 'node:stream';
import { ProductsController } from './products.controller';
import { ProductsService } from './products.service';
import type { CloudinaryUploadResult } from './services/cloudinary.service';

describe('ProductsController: carpetas de carga de imágenes', () => {
  let controller: ProductsController;
  let uploadImage: jest.MockedFunction<ProductsService['uploadImage']>;
  const response: CloudinaryUploadResult = {
    public_id: 'products/prueba',
    secure_url: 'https://images.example.test/product.png',
    url: 'http://images.example.test/product.png',
    bytes: 3,
    format: 'png',
    original_filename: 'producto',
    resource_type: 'image',
  };
  const image: Express.Multer.File = {
    fieldname: 'file',
    originalname: 'producto.png',
    encoding: '7bit',
    mimetype: 'image/png',
    size: 3,
    buffer: Buffer.from([1, 2, 3]),
    stream: Readable.from([]),
    destination: '',
    filename: '',
    path: '',
  };

  beforeEach(() => {
    uploadImage = jest.fn<
      ReturnType<ProductsService['uploadImage']>,
      Parameters<ProductsService['uploadImage']>
    >();
    uploadImage.mockResolvedValue(response);
    controller = new ProductsController(
      { uploadImage } as unknown as ProductsService,
      new ConfigService({ CLOUDINARY_UPLOAD_FOLDER: 'custom/products' }),
    );
  });

  it.each([
    ['products', 'custom/products'],
    ['  products  ', 'custom/products'],
    ['banner', 'sport-center/banner'],
    ['custom/products', 'custom/products'],
    [undefined, undefined],
  ])(
    'conserva el destino permitido %s y la respuesta del servicio',
    async (folder, expected) => {
      await expect(controller.uploadImage(image, folder)).resolves.toBe(
        response,
      );
      expect(uploadImage).toHaveBeenCalledWith(image, expected);
    },
  );

  it.each(['constructor', 'toString', '__proto__', 'otra-carpeta'])(
    'rechaza %s sin enviar el archivo al proveedor',
    async (folder) => {
      await expect(controller.uploadImage(image, folder)).rejects.toThrow(
        'Carpeta no permitida',
      );
      expect(uploadImage).not.toHaveBeenCalled();
    },
  );

  it('rechaza la ausencia de archivo sin llamar al proveedor', async () => {
    await expect(
      controller.uploadImage(undefined as unknown as Express.Multer.File),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(uploadImage).not.toHaveBeenCalled();
  });
});
