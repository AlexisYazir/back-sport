import { Controller, Post, Body, Get, Param } from '@nestjs/common';
import { ProductsService } from './products.service';

import { CreateProductDto } from './dto/product/create-product.dto';
import { CreateAttributeDto } from './dto/product/create-attribute.dto';
import { CreateVarAttributeValuesDto } from './dto/product/create-var-att_vls.dto';
import { CreateProductVariantDto } from './dto/product/create-product_variant.dto';
import { UpdateProductInvDto } from './dto/product/update-product-inv.dto';

import { CreateCategorieDto } from './dto/categories/create-categorie.dto';
import { UpdateCategorieDto } from './dto/categories/update-categorie.dto';

import { CreateMarcaDto } from './dto/marca/create-marca.tdo';
import { UpdateMarcaDto } from './dto/marca/update-marca.dto';

@Controller('products')
export class ProductsController {
  constructor(private readonly productsService: ProductsService) {}

  //* Funciones para productos
  @Post('create-product')
  async createProduct(@Body() createProductDto: CreateProductDto) {
    return this.productsService.createProduct(createProductDto);
  }

  @Post('create-product-variant')
  async createProductVariant(
    @Body() createProductVariantDto: CreateProductVariantDto,
  ) {
    return this.productsService.createProductVariant(createProductVariantDto);
  }

  @Post('create-variant-attribute-values')
  async createVariantAttributeValue(
    @Body() createVarAttributeValuesDto: CreateVarAttributeValuesDto,
  ) {
    return this.productsService.createVariantAttributeValue(
      createVarAttributeValuesDto,
    );
  }

  @Post('create-attribute')
  async createAttribute(@Body() createAttributeDto: CreateAttributeDto) {
    return this.productsService.createAttribute(createAttributeDto);
  }

  @Post('update-product-inventory')
  async updateProductInventory(
    @Body() updateProductInvDto: UpdateProductInvDto,
  ) {
    return this.productsService.updateProductInv(updateProductInvDto);
  }

  @Get('get-all-products')
  async getAllProducts() {
    return this.productsService.getAllProducts();
  }

  @Get('get-product-details/:id')
  async getProductDetail(@Param('id') id: number) {
    return this.productsService.getProductDetail(+id);
  }

  @Get('get-inventory-products')
  async getInventoryProducts() {
    return this.productsService.getInventoryProducts();
  }

  @Get('get-recient-products')
  async getRecientProducts() {
    return this.productsService.getRecientProducts();
  }

  @Get('get-variants-by-product/:id')
  async getVariantsByProduct(@Param('id') id: number) {
    return this.productsService.getVariantsByProduct(+id);
  }

  @Get('get-products-without-variants-attributes')
  async getProductsWithoutVariantsAttributes() {
    return this.productsService.getProductsWithoutVariantsAttributes();
  }

  //* Funciones para marcas
  @Post('create-marca')
  async createMarca(@Body() createMarcaDto: CreateMarcaDto) {
    return this.productsService.createMarca(createMarcaDto);
  }

  @Get('get-all-marcas')
  async getMarcas() {
    return this.productsService.getMarcas();
  }

  @Post('update-marca')
  async updateMarca(@Body() updateMarcaDto: UpdateMarcaDto) {
    return this.productsService.updateMarca(updateMarcaDto);
  }

  //* Funciones para categorias
  @Post('create-categorie')
  async createCategorie(@Body() createCategorieDto: CreateCategorieDto) {
    return this.productsService.createCategory(createCategorieDto);
  }

  @Get('get-all-categories')
  async getCategories() {
    return this.productsService.getCategories();
  }

  @Post('update-categorie')
  async updateCategorie(@Body() updateCategorieDto: UpdateCategorieDto) {
    return this.productsService.updateCategory(updateCategorieDto);
  }

  //* Funciones para atributos
  @Get('get-all-attributes')
  async getAttributes() {
    return this.productsService.getAttributes();
  }
}
