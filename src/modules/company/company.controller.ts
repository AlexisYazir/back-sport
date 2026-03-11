import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  ParseIntPipe,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { CompanyService } from './company.service';
import { CreateCompanyDto } from './dto/create-company.dto';
import { UpdateCompanyDto } from './dto/update-company.dto';
import { CreateFaqDto } from './dto/create-faq.dto';
import { UpdateFaqDto } from './dto/update-faq.dto';
import { CreateContactMessageDto } from './dto/create-contact-message.dto';
import { UpdateContactMessageDto } from './dto/update-contact-message.dto';

@Controller('company')
export class CompanyController {
  constructor(private readonly companyService: CompanyService) {}

  // ========== COMPANY INFO ==========
  @Get('info')
  async getCompanyInfo() {
    return this.companyService.getCompanyInfo();
  }

  @Post('info')
  @UseGuards(AuthGuard('jwt'))
  async createCompanyInfo(@Body() createCompanyDto: CreateCompanyDto) {
    return this.companyService.createCompanyInfo(createCompanyDto);
  }

  @Patch('info')
  @UseGuards(AuthGuard('jwt'))
  async updateCompanyInfo(@Body() updateCompanyDto: UpdateCompanyDto) {
    return this.companyService.updateCompanyInfo(updateCompanyDto);
  }

  // ========== FAQS ==========
  @Get('faqs')
  async getAllFaqs(@Query('activo') activo?: string) {
    const activoBool =
      activo === 'true' ? true : activo === 'false' ? false : undefined;
    return this.companyService.getAllFaqs(activoBool);
  }

  @Get('faqs/destacadas')
  async getFaqsDestacadas() {
    return this.companyService.getFaqsDestacadas();
  }

  @Get('faqs/seccion/:seccion')
  async getFaqsBySeccion(@Param('seccion') seccion: string) {
    return this.companyService.getFaqsBySeccion(seccion);
  }

  @Get('faqs/:id')
  async getFaqById(@Param('id', ParseIntPipe) id: number) {
    return this.companyService.getFaqById(id);
  }

  @Post('faqs')
  @UseGuards(AuthGuard('jwt'))
  async createFaq(@Body() createFaqDto: CreateFaqDto) {
    return this.companyService.createFaq(createFaqDto);
  }

  @Patch('faqs/:id')
  @UseGuards(AuthGuard('jwt'))
  async updateFaq(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateFaqDto: UpdateFaqDto,
  ) {
    return this.companyService.updateFaq(id, updateFaqDto);
  }

  @Delete('faqs/:id')
  @UseGuards(AuthGuard('jwt'))
  async deleteFaq(@Param('id', ParseIntPipe) id: number) {
    return this.companyService.deleteFaq(id);
  }

  @Post('faqs/:id/util')
  async marcarComoUtil(@Param('id', ParseIntPipe) id: number) {
    return this.companyService.marcarComoUtil(id);
  }

  // ========== CONTACT MESSAGES ==========
  @Post('contact')
  async createContactMessage(
    @Body() createContactMessageDto: CreateContactMessageDto,
  ) {
    return this.companyService.createContactMessage(createContactMessageDto);
  }

  @Get('contact')
  @UseGuards(AuthGuard('jwt'))
  async getAllContactMessages(@Query('leido') leido?: string) {
    const leidoBool =
      leido === 'true' ? true : leido === 'false' ? false : undefined;
    return this.companyService.getAllContactMessages(leidoBool);
  }

  @Get('contact/:id')
  @UseGuards(AuthGuard('jwt'))
  async getContactMessageById(@Param('id', ParseIntPipe) id: number) {
    return this.companyService.getContactMessageById(id);
  }

  @Patch('contact/:id')
  @UseGuards(AuthGuard('jwt'))
  async updateContactMessage(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateDto: UpdateContactMessageDto,
  ) {
    return this.companyService.updateContactMessage(id, updateDto);
  }

  @Delete('contact/:id')
  @UseGuards(AuthGuard('jwt'))
  async deleteContactMessage(@Param('id', ParseIntPipe) id: number) {
    return this.companyService.deleteContactMessage(id);
  }
}
