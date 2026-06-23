/* eslint-disable */
import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Not, Repository } from 'typeorm';

import { CreateCategorieDto } from '../dto/categories/create-categorie.dto';
import { UpdateCategorieDto } from '../dto/categories/update-categorie.dto';
import { CreateMarcaDto } from '../dto/marca/create-marca.tdo';
import { UpdateMarcaDto } from '../dto/marca/update-marca.dto';
import { Category } from '../entities/categorie/categorie.entity';
import { Marca } from '../entities/marca/marca.entity';
import { Sports } from '../entities/sports/sport.entity';

@Injectable()
export class ProductBrandCategoryService {
  constructor(
    @InjectRepository(Marca, 'editorConnection')
    private readonly marcaEditorRepository: Repository<Marca>,
    @InjectRepository(Category, 'editorConnection')
    private readonly categoryEditorRepository: Repository<Category>,

    @InjectRepository(Marca, 'readerConnection')
    private readonly marcaReaderRepository: Repository<Marca>,
    @InjectRepository(Category, 'readerConnection')
    private readonly categoryReaderRepository: Repository<Category>,
    @InjectRepository(Sports, 'readerConnection')
    private readonly sportReaderRepository: Repository<Sports>,
  ) {}

  async createMarca(dto: CreateMarcaDto): Promise<Marca> {
    const marca = await this.marcaReaderRepository.findOneBy({
      nombre: dto.nombre,
    });

    if (marca) {
      throw new BadRequestException('La marca ya existe');
    }

    const variant = this.marcaEditorRepository.create({
      nombre: dto.nombre,
      imagen: dto.imagen,
    });

    return await this.marcaEditorRepository.save(variant);
  }

  async updateMarca(dto: UpdateMarcaDto): Promise<Marca> {
    const marca = await this.marcaReaderRepository.findOne({
      where: { id_marca: dto.id_marca },
    });

    if (!marca) {
      throw new BadRequestException('La marca no existe');
    }

    if (dto.nombre && dto.nombre !== marca.nombre) {
      const existe = await this.marcaReaderRepository.findOneBy({
        nombre: dto.nombre,
      });

      if (existe) {
        throw new BadRequestException('Ya existe una marca con ese nombre');
      }
    }

    this.marcaEditorRepository.merge(marca, dto);

    return await this.marcaEditorRepository.save(marca);
  }

  async getMarcas(): Promise<Marca[]> {
    return await this.marcaReaderRepository.find({
      order: { nombre: 'ASC' },
    });
  }

  async createCategory(dto: CreateCategorieDto): Promise<Category> {
    const category = await this.categoryReaderRepository.findOneBy({
      nombre: dto.nombre,
    });

    if (category) {
      throw new BadRequestException('La categoría ya existe');
    }

    const variant = this.categoryEditorRepository.create({
      nombre: dto.nombre,
      id_padre: dto.id_padre,
    });

    return await this.categoryEditorRepository.save(variant);
  }

  async updateCategory(dto: UpdateCategorieDto): Promise<Category> {
    const category = await this.categoryReaderRepository.findOne({
      where: { id_categoria: dto.id_categoria },
    });

    if (!category) {
      throw new BadRequestException('La categoría no existe');
    }

    const categoryName = await this.categoryReaderRepository.findOne({
      where: {
        nombre: dto.nombre,
        id_categoria: Not(dto.id_categoria),
      },
    });

    if (categoryName) {
      throw new BadRequestException('Ya existe una categoría con ese nombre');
    }

    this.categoryEditorRepository.merge(category, dto);

    return await this.categoryEditorRepository.save(category);
  }

  async getCategories(): Promise<Category[]> {
    return await this.categoryReaderRepository.find();
  }

  async getCategoriesByParent(parentId: number): Promise<Category[]> {
    return await this.categoryReaderRepository.find({
      where: { id_padre: parentId },
      order: { nombre: 'ASC' },
    });
  }

  async getSports(): Promise<Sports[]> {
    return await this.sportReaderRepository.find({
      order: { nombre: 'ASC' },
    });
  }

  async getCompleteMenu(): Promise<any> {
    const [sports, clothing, accessories, brands] = await Promise.all([
      this.getSports(),
      this.getCategoriesByParent(1),
      this.getCategoriesByParent(34),
      this.getMarcas(),
    ]);

    return {
      sports,
      clothing,
      accessories,
      brands,
    };
  }
}
