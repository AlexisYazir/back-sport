/* eslint-disable */
import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';
import { CompanyInfo } from './entities/company-info.entity';
import { Faq } from './entities/faq.entity';
import { ContactMessage } from './entities/contact-message.entity';
import { CreateCompanyDto } from './dto/create-company.dto';
import { UpdateCompanyDto } from './dto/update-company.dto';
import { CreateFaqDto } from './dto/create-faq.dto';
import { UpdateFaqDto } from './dto/update-faq.dto';
import { CreateContactMessageDto } from './dto/create-contact-message.dto';
import { UpdateContactMessageDto } from './dto/update-contact-message.dto';

@Injectable()
export class CompanyService {
  constructor(
    @InjectRepository(CompanyInfo, 'editorConnection')
    private readonly companyEditorRepository: Repository<CompanyInfo>,

    @InjectRepository(CompanyInfo, 'readerConnection')
    private readonly companyReaderRepository: Repository<CompanyInfo>,

    @InjectRepository(Faq, 'editorConnection')
    private readonly faqEditorRepository: Repository<Faq>,

    @InjectRepository(Faq, 'readerConnection')
    private readonly faqReaderRepository: Repository<Faq>,

    @InjectRepository(ContactMessage, 'editorConnection')
    private readonly contactEditorRepository: Repository<ContactMessage>,

    @InjectRepository(ContactMessage, 'readerConnection')
    private readonly contactReaderRepository: Repository<ContactMessage>,

    @InjectDataSource('editorConnection')
    private readonly editorDataSource: DataSource,

    @InjectDataSource('readerConnection')
    private readonly readerDataSource: DataSource,
  ) {}

  // ========== COMPANY INFO ==========
  async getCompanyInfo(): Promise<CompanyInfo> {
    const company = await this.companyReaderRepository.findOne({
      where: { id_empresa: 1 },
    });

    if (!company) {
      throw new NotFoundException('Información de empresa no encontrada');
    }

    return company;
  }

  async createCompanyInfo(
    createCompanyDto: CreateCompanyDto,
  ): Promise<CompanyInfo> {
    const existing = await this.companyReaderRepository.findOne({
      where: { id_empresa: 1 },
    });

    if (existing) {
      throw new BadRequestException(
        'La información de empresa ya existe. Use PATCH para actualizar.',
      );
    }

    const company = this.companyEditorRepository.create({
      ...createCompanyDto,
      id_empresa: 1,
    });

    return await this.companyEditorRepository.save(company);
  }

  async updateCompanyInfo(
    updateCompanyDto: UpdateCompanyDto,
  ): Promise<CompanyInfo> {
    const company = await this.companyReaderRepository.findOne({
      where: { id_empresa: 1 },
    });

    if (!company) {
      // Si no existe, crear una nueva
      return this.createCompanyInfo(updateCompanyDto as CreateCompanyDto);
    }

    Object.assign(company, updateCompanyDto);
    company.updated_at = new Date();

    return await this.companyEditorRepository.save(company);
  }

  // ========== HOME BANNER ==========
  async getActiveBannerImages(): Promise<any[]> {
    return this.readerDataSource.query(`
      SELECT
        id_banner,
        url_imagen,
        cloudinary_public_id,
        titulo,
        descripcion,
        alt_text,
        orden,
        activo,
        fecha_creacion,
        fecha_actualizacion
      FROM core.home_banner_images
      WHERE activo = true
      ORDER BY orden ASC, id_banner ASC
      LIMIT 4;
    `);
  }

  async getAdminBannerImages(): Promise<any[]> {
    return this.readerDataSource.query(`
      SELECT
        id_banner,
        url_imagen,
        cloudinary_public_id,
        titulo,
        descripcion,
        alt_text,
        orden,
        activo,
        creado_por,
        actualizado_por,
        fecha_creacion,
        fecha_actualizacion
      FROM core.home_banner_images
      ORDER BY activo DESC, orden ASC, id_banner DESC;
    `);
  }

  async createBannerImage(dto: any, userId?: number): Promise<any> {
    const url = this.cleanRequiredText(dto?.url_imagen, 1200);
    const active = dto?.activo !== false;

    if (active) {
      await this.validateActiveBannerLimit();
    }

    const rows = await this.editorDataSource.query(
      `
      INSERT INTO core.home_banner_images (
        url_imagen,
        cloudinary_public_id,
        titulo,
        descripcion,
        alt_text,
        orden,
        activo,
        creado_por,
        actualizado_por,
        fecha_creacion,
        fecha_actualizacion
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      RETURNING *;
      `,
      [
        url,
        this.cleanOptionalText(dto?.cloudinary_public_id, 255),
        this.cleanOptionalText(dto?.titulo, 120),
        this.cleanOptionalText(dto?.descripcion, 255),
        this.cleanOptionalText(dto?.alt_text, 180),
        this.toPositiveInteger(dto?.orden, 1),
        active,
        userId || null,
      ],
    );

    return rows[0];
  }

  async updateBannerImage(id: number, dto: any, userId?: number): Promise<any> {
    if (!Number.isInteger(Number(id)) || Number(id) <= 0) {
      throw new BadRequestException('El banner debe ser válido');
    }

    const existingRows = await this.readerDataSource.query(
      `
      SELECT id_banner, activo
      FROM core.home_banner_images
      WHERE id_banner = $1
      LIMIT 1;
      `,
      [id],
    );

    if (!existingRows[0]) {
      throw new NotFoundException('Imagen de banner no encontrada');
    }

    if (dto?.activo === true && existingRows[0].activo !== true) {
      await this.validateActiveBannerLimit(Number(id));
    }

    const rows = await this.editorDataSource.query(
      `
      UPDATE core.home_banner_images
      SET url_imagen = COALESCE($2, url_imagen),
          cloudinary_public_id = COALESCE($3, cloudinary_public_id),
          titulo = COALESCE($4, titulo),
          descripcion = COALESCE($5, descripcion),
          alt_text = COALESCE($6, alt_text),
          orden = COALESCE($7, orden),
          activo = COALESCE($8, activo),
          actualizado_por = $9,
          fecha_actualizacion = CURRENT_TIMESTAMP
      WHERE id_banner = $1
      RETURNING *;
      `,
      [
        id,
        dto?.url_imagen ? this.cleanRequiredText(dto.url_imagen, 1200) : null,
        dto?.cloudinary_public_id !== undefined
          ? this.cleanOptionalText(dto.cloudinary_public_id, 255)
          : null,
        dto?.titulo !== undefined ? this.cleanOptionalText(dto.titulo, 120) : null,
        dto?.descripcion !== undefined
          ? this.cleanOptionalText(dto.descripcion, 255)
          : null,
        dto?.alt_text !== undefined ? this.cleanOptionalText(dto.alt_text, 180) : null,
        dto?.orden !== undefined ? this.toPositiveInteger(dto.orden, 1) : null,
        dto?.activo !== undefined ? Boolean(dto.activo) : null,
        userId || null,
      ],
    );

    return rows[0];
  }

  async deleteBannerImage(id: number): Promise<{ message: string }> {
    if (!Number.isInteger(Number(id)) || Number(id) <= 0) {
      throw new BadRequestException('El banner debe ser válido');
    }

    const result = await this.editorDataSource.query(
      `
      DELETE FROM core.home_banner_images
      WHERE id_banner = $1
      RETURNING id_banner;
      `,
      [id],
    );

    if (!result[0]) {
      throw new NotFoundException('Imagen de banner no encontrada');
    }

    return { message: 'Imagen de banner eliminada correctamente' };
  }

  private async validateActiveBannerLimit(excludeId?: number): Promise<void> {
    const rows = await this.readerDataSource.query(
      `
      SELECT COUNT(*)::int AS total
      FROM core.home_banner_images
      WHERE activo = true
        AND ($1::int IS NULL OR id_banner <> $1::int);
      `,
      [excludeId || null],
    );

    if (Number(rows[0]?.total || 0) >= 4) {
      throw new BadRequestException(
        'Solo puedes tener máximo 4 imágenes activas en el banner',
      );
    }
  }

  // ========== FAQS ==========
  async getAllFaqs(activo?: boolean): Promise<Faq[]> {
    const where: any = {};
    if (activo !== undefined) {
      where.activo = activo;
    }

    return await this.faqReaderRepository.find({
      where,
      order: {
        seccion: 'ASC',
        orden: 'ASC',
      },
    });
  }

  async getFaqById(id: number): Promise<Faq> {
    const faq = await this.faqReaderRepository.findOne({
      where: { id_faq: id },
    });

    if (!faq) {
      throw new NotFoundException('Pregunta frecuente no encontrada');
    }

    // Incrementar contador de vistas
    await this.faqEditorRepository.increment(
      { id_faq: id },
      'contador_vistas',
      1,
    );

    return faq;
  }

  async getFaqsBySeccion(seccion: string): Promise<Faq[]> {
    return await this.faqReaderRepository.find({
      where: { seccion, activo: true },
      order: { orden: 'ASC' },
    });
  }

  async getFaqsDestacadas(): Promise<Faq[]> {
    return await this.faqReaderRepository.find({
      where: { destacado: true, activo: true },
      order: { orden: 'ASC' },
    });
  }

  async createFaq(createFaqDto: CreateFaqDto): Promise<Faq> {
    // Verificar si ya existe una pregunta similar
    const existing = await this.faqReaderRepository.findOne({
      where: { pregunta: createFaqDto.pregunta },
    });

    if (existing) {
      throw new BadRequestException(
        'Ya existe una pregunta frecuente con ese texto',
      );
    }

    const faq = this.faqEditorRepository.create(createFaqDto);
    return await this.faqEditorRepository.save(faq);
  }

  async updateFaq(id: number, updateFaqDto: UpdateFaqDto): Promise<Faq> {
    const faq = await this.faqReaderRepository.findOne({
      where: { id_faq: id },
    });

    if (!faq) {
      throw new NotFoundException('Pregunta frecuente no encontrada');
    }

    // Si está cambiando la pregunta, verificar duplicado
    if (updateFaqDto.pregunta && updateFaqDto.pregunta !== faq.pregunta) {
      const existing = await this.faqReaderRepository.findOne({
        where: { pregunta: updateFaqDto.pregunta },
      });

      if (existing) {
        throw new BadRequestException(
          'Ya existe una pregunta frecuente con ese texto',
        );
      }
    }

    Object.assign(faq, updateFaqDto);
    faq.updated_at = new Date();

    return await this.faqEditorRepository.save(faq);
  }

  async deleteFaq(id: number): Promise<{ message: string }> {
    const faq = await this.faqReaderRepository.findOne({
      where: { id_faq: id },
    });

    if (!faq) {
      throw new NotFoundException('Pregunta frecuente no encontrada');
    }

    await this.faqEditorRepository.delete(id);
    return { message: 'Pregunta frecuente eliminada correctamente' };
  }

  async marcarComoUtil(id: number): Promise<{ message: string }> {
    const faq = await this.faqReaderRepository.findOne({
      where: { id_faq: id },
    });

    if (!faq) {
      throw new NotFoundException('Pregunta frecuente no encontrada');
    }

    await this.faqEditorRepository.increment(
      { id_faq: id },
      'contador_util',
      1,
    );
    return { message: 'Gracias por tu retroalimentación' };
  }

  // ========== CONTACT MESSAGES ==========
  async createContactMessage(
    createContactMessageDto: CreateContactMessageDto,
  ): Promise<ContactMessage> {
    const message = this.contactEditorRepository.create(
      createContactMessageDto,
    );
    return await this.contactEditorRepository.save(message);
  }

  async getAllContactMessages(leido?: boolean): Promise<ContactMessage[]> {
    const where: any = {};
    if (leido !== undefined) {
      where.leido = leido;
    }

    return await this.contactReaderRepository.find({
      where,
      order: { created_at: 'DESC' },
      relations: ['usuario_responde'],
    });
  }

  async getContactMessageById(id: number): Promise<ContactMessage> {
    const message = await this.contactReaderRepository.findOne({
      where: { id_mensaje: id },
      relations: ['usuario_responde'],
    });

    if (!message) {
      throw new NotFoundException('Mensaje de contacto no encontrado');
    }

    // Marcar como leído si no lo estaba
    if (!message.leido) {
      message.leido = true;
      message.fecha_lectura = new Date();
      await this.contactEditorRepository.save(message);
    }

    return message;
  }

  async updateContactMessage(
    id: number,
    updateDto: UpdateContactMessageDto,
  ): Promise<ContactMessage> {
    const message = await this.contactReaderRepository.findOne({
      where: { id_mensaje: id },
    });

    if (!message) {
      throw new NotFoundException('Mensaje de contacto no encontrado');
    }

    Object.assign(message, updateDto);
    return await this.contactEditorRepository.save(message);
  }

  async deleteContactMessage(id: number): Promise<{ message: string }> {
    const message = await this.contactReaderRepository.findOne({
      where: { id_mensaje: id },
    });

    if (!message) {
      throw new NotFoundException('Mensaje de contacto no encontrado');
    }

    await this.contactEditorRepository.delete(id);
    return { message: 'Mensaje eliminado correctamente' };
  }

  private cleanRequiredText(value: unknown, maxLength: number): string {
    const cleaned = this.cleanOptionalText(value, maxLength);
    if (!cleaned) {
      throw new BadRequestException('La URL de imagen es obligatoria');
    }
    return cleaned;
  }

  private cleanOptionalText(value: unknown, maxLength: number): string | null {
    if (value === undefined || value === null) return null;
    const cleaned = String(value)
      .replace(/[\u0000-\u001f\u007f]/g, '')
      .trim()
      .slice(0, maxLength);

    return cleaned || null;
  }

  private toPositiveInteger(value: unknown, fallback: number): number {
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
    return Math.floor(parsed);
  }
}
