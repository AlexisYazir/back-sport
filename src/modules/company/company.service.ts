/* eslint-disable */
import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
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
}
