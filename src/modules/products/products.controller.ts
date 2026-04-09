import {
  Controller,
  Post,
  Body,
  Get,
  Param,
  HttpCode,
  HttpStatus,
  Put,
  UseGuards,
  UploadedFile,
  UseInterceptors,
  BadRequestException,
  ParseFilePipe,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { ProductsService } from './products.service';

import { CreateProductDto } from './dto/product/create-product.dto';
import { CreateProductSportsDto } from './dto/product/create-product-sports.dto';
import { CreateAttributeDto } from './dto/product/create-attribute.dto';
import { CreateVarAttributeValuesDto } from './dto/product/create-var-att_vls.dto';
import { CreateProductVariantDto } from './dto/product/create-product_variant.dto';
import { UpdateProductInvDto } from './dto/product/update-product-inv.dto';
import { UpdateProductFullDto } from './dto/product/update-product-full.dto';
import { UpdateProductVariantAttributeDto } from './dto/product/update.product-var-attr.dto';

import { CreateCategorieDto } from './dto/categories/create-categorie.dto';
import { UpdateCategorieDto } from './dto/categories/update-categorie.dto';

import { CreateMarcaDto } from './dto/marca/create-marca.tdo';
import { UpdateMarcaDto } from './dto/marca/update-marca.dto';
import { Roles } from '../../services/auth/roles.decorator';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../../services/auth/roles.guard';

import { CreateInventoryMovementDto } from './dto/inventory/create-inventory_movement.dto';
import { CreateInventoryMovementSkuDto } from './dto/inventory/create-inventory-movement-sku.dto';

@Controller('products')
export class ProductsController {
  constructor(private readonly productsService: ProductsService) {}

  //* Funciones para productos
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-product')
  async createProduct(@Body() createProductDto: CreateProductDto) {
    return this.productsService.createProduct(createProductDto);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('assign-product-sports')
  async assignProductSports(@Body() dto: CreateProductSportsDto) {
    return this.productsService.assignProductSports(dto);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('upload-image')
  @UseInterceptors(
    FileInterceptor('file', {
      storage: memoryStorage(),
      limits: {
        files: 1,
        fileSize: 2 * 1024 * 1024,
        fields: 5,
      },
      fileFilter: (_req, file, callback) => {
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp'];

        if (!allowedMimeTypes.includes(file.mimetype)) {
          return callback(
            new BadRequestException(
              'Solo se permiten imágenes JPG, PNG o WEBP',
            ),
            false,
          );
        }

        callback(null, true);
      },
    }),
  )
  async uploadImage(
    @UploadedFile(
      new ParseFilePipe({
        validators: [],
        fileIsRequired: true,
        exceptionFactory: () =>
          new BadRequestException('Debe enviar una imagen válida'),
      }),
    )
    file: Express.Multer.File,
    @Body('folder') folder?: string,
  ) {
    if (!file) {
      throw new BadRequestException('No se recibió ningún archivo');
    }

    const allowedFolders = ['products', 'categories', 'temp'];
    if (folder && !allowedFolders.includes(folder)) {
      throw new BadRequestException('Carpeta no permitida');
    }

    return this.productsService.uploadImage(file, folder);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-product-variant')
  async createProductVariant(
    @Body() createProductVariantDto: CreateProductVariantDto,
  ) {
    return this.productsService.createProductVariant(createProductVariantDto);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-variant-attribute-values')
  async createVariantAttributeValue(
    @Body() createVarAttributeValuesDto: CreateVarAttributeValuesDto,
  ) {
    return this.productsService.createVariantAttributeValue(
      createVarAttributeValuesDto,
    );
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-inventory-movement')
  async createInventoryMovement(
    @Body() createInventoryMovementDto: CreateInventoryMovementDto,
  ) {
    return this.productsService.createInventoryMovement(
      createInventoryMovementDto,
    );
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('inventory-movements/bulk')
  async bulkCreateInventoryMovements(
    @Body() body: { movements: CreateInventoryMovementSkuDto[] },
  ) {
    return this.productsService.bulkCreateInventoryMovements(body.movements);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('inventory-movements')
  async getInventoryMovements() {
    return this.productsService.getInventoryMovements();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('inventory-movements/variants')
  async getVariantsForInventoryMovement() {
    return this.productsService.getVariantsForInventoryMovement();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-attribute')
  async createAttribute(@Body() createAttributeDto: CreateAttributeDto) {
    console.log(createAttributeDto);
    return this.productsService.createAttribute(createAttributeDto);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Put('update-product-inventory')
  async updateProductInventory(
    @Body() updateProductInvDto: UpdateProductInvDto,
  ) {
    return this.productsService.updateProductInv(updateProductInvDto);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Put('update-product-full')
  @HttpCode(HttpStatus.OK)
  async updateProductFull(@Body() dto: UpdateProductFullDto) {
    const result = await this.productsService.updateProductFull(dto);

    return {
      message: 'Producto base actualizado correctamente',
      data: result,
    };
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Put('update-product-variant')
  @HttpCode(HttpStatus.OK)
  async updateProductVariant(@Body() dto: UpdateProductVariantAttributeDto) {
    const result = await this.productsService.updateProductVariant(dto);

    return {
      message:
        'Datos de producto: variante y atributos actualizados correctamente',
      data: result,
    };
  }

  @Get('get-all-products')
  async getAllProducts() {
    return this.productsService.getAllProducts();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(2, 3)
  @Get('get-all-orders')
  async getAllOrders() {
    return this.productsService.getAllOrders();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(2, 3)
  @Get('get-order-details/:id')
  async getOrderDetail(@Param('id') id: string) {
    return this.productsService.getOrderDetail(Number(id));
  }

  @Get('get-product-details/:id')
  async getProductDetail(@Param('id') id: number) {
    return this.productsService.getProductDetail(+id);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('get-inventory-products')
  async getInventoryProducts() {
    return this.productsService.getInventoryProducts();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('get-recient-products')
  async getRecientProducts() {
    return this.productsService.getRecientProducts();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('get-variants-by-product/:id')
  async getVariantsByProduct(@Param('id') id: number) {
    return this.productsService.getVariantsByProduct(+id);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('get-products-without-variants-attributes')
  async getProductsWithoutVariantsAttributes() {
    return this.productsService.getProductsWithoutVariantsAttributes();
  }

  //* Funciones para marcas
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-marca')
  async createMarca(@Body() createMarcaDto: CreateMarcaDto) {
    return this.productsService.createMarca(createMarcaDto);
  }

  @Get('get-all-marcas')
  async getMarcas() {
    return this.productsService.getMarcas();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('update-marca')
  async updateMarca(@Body() updateMarcaDto: UpdateMarcaDto) {
    return this.productsService.updateMarca(updateMarcaDto);
  }

  //* Funciones para categorias
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Post('create-categorie')
  async createCategorie(@Body() createCategorieDto: CreateCategorieDto) {
    return this.productsService.createCategory(createCategorieDto);
  }

  @Get('get-all-categories')
  async getCategories() {
    return this.productsService.getCategories();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Put('update-categorie')
  async updateCategorie(@Body() updateCategorieDto: UpdateCategorieDto) {
    return this.productsService.updateCategory(updateCategorieDto);
  }

  //* Funciones para atributos
  @Get('get-all-attributes')
  async getAttributes() {
    return this.productsService.getAttributes();
  }

  //* Funciones para ordenes
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(2, 3)
  @Get('get-all-orders')
  async getOrdersEmployee() {
    return this.productsService.getOrderss();
  }

  //* PARA EL MENU
  @Get('menu/categories-by-parent/:parentId')
  async getCategoriesByParent(@Param('parentId') parentId: number) {
    return this.productsService.getCategoriesByParent(+parentId);
  }

  @Get('menu/sports')
  async getSports() {
    return this.productsService.getSports();
  }

  @Get('menu/brands')
  async getBrands() {
    return this.productsService.getMarcas();
  }

  @Get('menu/complete-menu')
  async getCompleteMenu() {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return this.productsService.getCompleteMenu();
  }
}
